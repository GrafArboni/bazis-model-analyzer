// Анализ модели — загрузчик защищённой сборки.
// Сам анализ лежит рядом в «Анализ модели.crypt» (AES-256-GCM). Его расшифровывает crypt_svc.exe: ключа в нём нет —
// ключ выдаёт сервер лицензий автора по license.lic (лицензия на этот компьютер; срок и отзыв — на сервере).
// Ответ сервера хранится, и без интернета скрипт работает до 14 дней. Открытый текст на диск не пишется: он приходит
// по каналу от crypt_svc и исполняется из памяти. Нет лицензии — загрузчик покажет код компьютера для автора.
var AN_LOADER_BUILD = 8;
var AN_SCRIPT_DIR = '';
var AN_LICENSE = null;

(function () {
    var fs = require('fs'), path = require('path'), os = require('os'), cp = require('child_process');
    var CRYPT = 'Анализ модели.crypt', SVC = 'crypt_svc.exe', LIC = 'license.lic', SELF = 'Анализ модели.js';
    var LIVE_DIR = 'S:\\Bazis\\Scripts\\13 Анализ модели';
    var NL = '\n';
    var logFile = '', child = null, timers = [], finished = false;

    function trace(t) {
        if (!logFile) { return; }
        try { fs.appendFileSync(logFile, new Date().toISOString().slice(11, 19) + ' ' + String(t) + '\r\n', 'utf8'); } catch (e) { }
    }
    function exists(p) {
        try { return fs.existsSync(p); } catch (e) { return false; }
    }
    function isScriptDir(d) {
        return !!d && (d != '.') && exists(path.join(d, CRYPT)) && exists(path.join(d, SVC));
    }
    function appDir() {
        var base = '';
        try { base = process.env.APPDATA || ''; } catch (e) { base = ''; }
        if (!base) { try { base = os.tmpdir(); } catch (e1) { base = '.'; } }
        var d = path.join(base, 'bazis_analyzer');
        try { if (!exists(d)) { fs.mkdirSync(d); } } catch (e2) { }
        return d;
    }
    function readJson(f) {
        try { return JSON.parse(String(fs.readFileSync(f, 'utf8')).replace(/^\uFEFF/, '')); } catch (e) { return null; }
    }
    function settingsText() {
        var c = [], i;
        try { c.push(path.join(path.dirname(process.execPath), 'Settings', 'Settings.xml')); } catch (e) { }
        try { c.push(path.join(process.cwd(), 'Settings', 'Settings.xml')); } catch (e1) { }
        for (i = 0; i < c.length; i++) {
            try { if (exists(c[i])) { return String(fs.readFileSync(c[i], 'utf8')); } } catch (e2) { }
        }
        return '';
    }
    function askDir() {
        try {
            alert('Анализ модели: не удалось определить папку скрипта.' + NL + NL +
                'Укажите папку, где лежат «' + SELF + '», «' + CRYPT + '» и «' + SVC + '». Скрипт её запомнит.');
            for (var i = 0; i < 3; i++) {
                var d = '';
                try { d = system.askFolder('Папка скрипта «Анализ модели»', ''); } catch (e) { trace('askFolder: ' + e.message); return ''; }
                if (!d) { return ''; }
                if (isScriptDir(d)) { return String(d); }
                if (!confirm('В папке' + NL + d + NL + 'нет «' + CRYPT + '» или «' + SVC + '».' + NL + 'Выбрать другую?')) { return ''; }
            }
        }
        catch (e1) {
            trace('askDir: ' + e1.message);
        }
        return '';
    }
    function resolveDir() {
        var c = [], i, a, m, found = '';
        try { if ((typeof __dirname !== 'undefined') && __dirname && (__dirname != '.')) { c.push(String(__dirname)); } } catch (e) { }
        try { if ((typeof module !== 'undefined') && module && module.filename) { c.push(path.dirname(module.filename)); } } catch (e1) { }
        try { if (require.main && require.main.filename) { c.push(path.dirname(require.main.filename)); } } catch (e2) { }
        try {
            for (i = 0; i < process.argv.length; i++) {
                a = String(process.argv[i]);
                if (/\.js$/i.test(a)) { c.push(path.dirname(a)); }
            }
        } catch (e3) { }
        try { c.push(process.cwd()); } catch (e4) { }
        var xml = settingsText(), re = /<Path>([^<]*\\Анализ модели\.js)<\/Path>/gi;
        while (xml && ((m = re.exec(xml)) !== null)) { c.push(path.dirname(m[1])); }
        var pf = path.join(appDir(), 'paths.json'), known = readJson(pf);
        if (known && known.scriptDir) { c.push(String(known.scriptDir)); }
        c.push(LIVE_DIR);
        for (i = 0; (i < c.length) && !found; i++) {
            try { if (isScriptDir(c[i])) { found = path.resolve(c[i]); } } catch (e5) { }
        }
        trace('папка скрипта: ' + (found || 'НЕ НАЙДЕНА') + '; кандидаты: ' + c.join(' | '));
        if (!found) {
            found = askDir();
            if (found) {
                try { fs.writeFileSync(pf, JSON.stringify({ scriptDir: found }), 'utf8'); } catch (e6) { }
            }
        }
        return found;
    }

    function later(fn, ms) {
        var id = setTimeout(fn, ms);
        timers.push(id);
        return id;
    }
    function stopAll() {
        for (var i = 0; i < timers.length; i++) { try { clearTimeout(timers[i]); } catch (e) { } }
        timers = [];
        if (child) { try { child.kill(); } catch (e1) { } }
        child = null;
    }
    function finish() {
        if (finished) { return; }
        finished = true;
        stopAll();
        try { Action.Finish(); } catch (e) { }
    }
    function fail(text) {
        trace('ОТКАЗ: ' + String(text).replace(/\s+/g, ' '));
        try { alert(text); } catch (e) { }
        finish();
    }

    // Запуск crypt_svc: cb(code, stdout: Buffer, stderr: string, error)
    function run(svc, args, cb) {
        var out = [], err = [], done = false, guard = null;
        function fin(code, e) {
            if (done) { return; }
            done = true;
            if (guard) { try { clearTimeout(guard); } catch (e0) { } }
            child = null;
            if (finished) { return; }
            try { cb(code, Buffer.concat(out), Buffer.concat(err).toString('utf8'), e); }
            catch (e1) { fail('Анализ модели — ошибка загрузчика, пришлите этот текст:' + NL + (e1 && e1.stack ? e1.stack : e1)); }
        }
        var ch = null;
        try { ch = cp.spawn(svc, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
        catch (e2) { fin(-1, e2); return; }
        child = ch;
        ch.stdout.on('data', function (d) { out.push(d); });
        ch.stderr.on('data', function (d) { err.push(d); });
        ch.on('error', function (e3) { fin(-1, e3); });
        ch.on('close', function (code) { fin(code, null); });
        guard = later(function () {
            trace('crypt_svc не ответил за 35 с — останавливаю');
            try { ch.kill(); } catch (e4) { }
            later(function () { fin(-2, new Error('crypt_svc не ответил за 35 секунд')); }, 3000);
        }, 35000);
    }

    function dateText(unix) {
        var d = new Date(Number(unix) * 1000);
        function two(n) { return (n < 10 ? '0' : '') + n; }
        return two(d.getDate()) + '.' + two(d.getMonth() + 1) + '.' + d.getFullYear();
    }

    // Нет лицензии / не та / истекла: показать код компьютера и что с ним делать.
    function licenseHelp(dir, svc, reason) {
        run(svc, ['id'], function (code, out, err, e) {
            var dev = String(out.toString('utf8')).replace(/\s+/g, '');
            if (code !== 0 || !/^[0-9a-f]{16,64}$/.test(dev)) {
                fail('Анализ модели: ' + reason + NL + NL + 'Код компьютера получить не удалось: ' + (e ? e.message : (err || 'код ' + code)));
                return;
            }
            var note = '';
            try {
                fs.writeFileSync(path.join(dir, 'Код компьютера.txt'), dev + '\r\n', 'utf8');
                note = NL + '(он же записан в файл «Код компьютера.txt» в папке скрипта)';
            } catch (e1) { }
            fail('Анализ модели: ' + reason + NL + NL +
                'Код этого компьютера:' + NL + dev + note + NL + NL +
                'Отправьте код автору скрипта. Полученный файл license.lic положите в папку скрипта:' + NL + dir);
        });
    }

    // Отказы, при которых нужен автор: показать код компьютера. Код ошибки — "[!] E_…:" в stderr crypt_svc.
    function explain(err) {
        var m;
        if (/E_EXPIRED/.test(err)) {
            m = /until=(\d+)/.exec(err);
            return 'срок лицензии истёк' + (m && Number(m[1]) > 0 ? ' ' + dateText(m[1]) : '') + '. Напишите автору, чтобы продлить.';
        }
        if (/E_REVOKED/.test(err)) { return 'лицензия отозвана автором.'; }
        if (/E_BLOCKED/.test(err)) { return 'лицензия заблокирована: проверки шли из слишком многих мест. Свяжитесь с автором.'; }
        if (/E_UNKNOWN/.test(err)) { return 'этой лицензии нет в списке автора.'; }
        if (/E_DEVICE/.test(err)) { return 'лицензия выписана на другой компьютер.'; }
        if (/E_OLDLIC/.test(err)) { return 'лицензия старого образца — нужна новая (с онлайн-проверкой).'; }
        if (/E_BADLIC|E_NOLIC/.test(err)) { return 'файл лицензии повреждён или не от этой программы.'; }
        return '';
    }
    // Отказы, которые человек решает сам (сеть, часы).
    function explainLocal(err) {
        var m;
        if (/E_OFFLINE_STALE/.test(err)) {
            m = /got=(\d+)/.exec(err);
            return 'скрипт работал без связи с сервером лицензий 14 дней' + (m ? ' (последняя проверка ' + dateText(m[1]) + ')' : '') + '.' + NL + NL +
                'Подключите интернет и запустите скрипт снова.';
        }
        if (/E_OFFLINE/.test(err)) {
            m = /\(([^)]*)\)/.exec(err);
            return 'нет связи с сервером лицензий' + (m ? ' (' + m[1] + ')' : '') + '.' + NL + NL +
                'Первый запуск и первый запуск после обновления требуют интернета; дальше скрипт работает без сети до 14 дней.' + NL +
                'Проверьте подключение и запустите снова.';
        }
        if (/E_CLOCK/.test(err)) { return 'часы компьютера переведены назад. Поставьте верные дату и время и запустите снова.'; }
        return '';
    }

    function runPayload(src) {
        if (src.charCodeAt(0) === 0xFEFF) { src = src.slice(1); }
        src += '\n//# sourceURL=analiz_modeli_payload.js';
        var ok = false;
        try {
            (0, eval)(src);
            ok = true;
        }
        catch (e) {
            if (!(e instanceof EvalError)) { throw e; }
            trace('eval недоступен: ' + e.message);
        }
        if (!ok) { require('vm').runInThisContext(src, { filename: 'analiz_modeli_payload.js' }); }
    }

    function main() {
        try { logFile = path.join(os.tmpdir(), 'bazis_analyzer_loader.log'); fs.writeFileSync(logFile, 'START ' + new Date().toISOString() + ' build ' + AN_LOADER_BUILD + '\r\n', 'utf8'); }
        catch (e) { logFile = ''; }
        var dir = resolveDir();
        if (!dir) {
            alert('Анализ модели: папка скрипта не найдена — запуск отменён.');
            return;
        }
        AN_SCRIPT_DIR = dir;
        var svc = path.join(dir, SVC), crypt = path.join(dir, CRYPT), lic = path.join(dir, LIC);
        // команду держим, пока crypt_svc расшифровывает (~0,1 с): после конца тела скрипта движок бы остановился
        Action.OnFinish = function () { finished = true; stopAll(); trace('команда прервана до запуска анализа'); };
        Action.Continue();
        try { Action.Hint = 'Анализ модели: проверка лицензии…'; } catch (e0) { }
        if (!exists(lic)) {
            licenseHelp(dir, svc, 'рядом со скриптом нет файла лицензии license.lic.');
            return;
        }
        var t0 = Date.now();
        run(svc, ['unpack', crypt, '-', lic], function (code, out, err, e) {
            if (code !== 0) {
                var why = explain(err);
                trace('crypt_svc: код ' + code + ' ' + String(err).replace(/\s+/g, ' ') + (e ? ' ' + e.message : ''));
                if (why) { licenseHelp(dir, svc, why); return; }
                var local = explainLocal(err);
                if (local) { fail('Анализ модели: ' + local); return; }
                if (/E_CORRUPT/.test(err)) {
                    fail('Анализ модели: файл «' + CRYPT + '» повреждён или от другой версии.' + NL + NL +
                        'Запустите двойным щелчком «Анализ_модели_UI.exe» из папки скрипта — он проверит и восстановит файлы.');
                    return;
                }
                fail('Анализ модели: не удалось запустить защищённый скрипт.' + NL + NL + (e ? e.message : (err || 'код ' + code)));
                return;
            }
            var m = /id=(\w+) until=(\d+) dev=([0-9a-f]+) checked=(\d+) online=(\d) left=(\d+)/.exec(err);
            if (m) { AN_LICENSE = { id: m[1], exp: Number(m[2]), dev: m[3], checked: Number(m[4]), online: m[5] === '1', left: Number(m[6]) }; }
            trace('расшифровано ' + out.length + ' байт за ' + (Date.now() - t0) + ' мс' + (m ? ', лицензия ' + m[1] + ' до ' + dateText(m[2]) +
                (m[5] === '1' ? ', проверена на сервере' : ', без сервера, осталось ' + m[6] + ' дн.') : ''));
            if (AN_LICENSE && !AN_LICENSE.online && AN_LICENSE.left <= 3) {
                try {
                    alert('Анализ модели: нет связи с сервером лицензий с ' + dateText(AN_LICENSE.checked) + '.' + NL +
                        'Без интернета скрипт проработает ещё ' + AN_LICENSE.left + ' дн. Подключите интернет, чтобы продлить проверку.');
                } catch (eA) { }
            }
            var src = out.toString('utf8');
            out = null;
            for (var i = 0; i < timers.length; i++) { try { clearTimeout(timers[i]); } catch (e1) { } }
            timers = [];
            runPayload(src);
            src = null;
            // анализ не перешёл в живой режим (ошибка, нет окна) — команду держать незачем
            var live = false;
            try { live = (typeof anLiveStopped !== 'undefined') && (anLiveStopped === false); } catch (e2) { live = false; }
            if (!live) { finished = true; try { Action.Finish(); } catch (e3) { } }
        });
    }

    try {
        main();
    }
    catch (eMain) {
        trace('ОШИБКА загрузчика: ' + (eMain && eMain.stack ? eMain.stack : eMain));
        try { alert('Анализ модели — ошибка загрузчика, пришлите этот текст:' + NL + (eMain && eMain.message ? eMain.message : eMain)); } catch (e9) { }
        finish();
    }
})();
