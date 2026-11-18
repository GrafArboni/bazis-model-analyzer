// Анализ модели — загрузчик защищённой сборки.
// Сам анализ лежит рядом в «Анализ модели.crypt» (AES-256-GCM). Его расшифровывает crypt_svc.exe, и только если рядом
// есть license.lic — лицензия, выписанная на этот компьютер. Открытый текст на диск не пишется: он приходит по каналу
// от crypt_svc и исполняется из памяти. Нет лицензии — загрузчик покажет код компьютера, который надо отправить автору.
var AN_LOADER_BUILD = 2;
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
            trace('crypt_svc не ответил за 20 с — останавливаю');
            try { ch.kill(); } catch (e4) { }
            later(function () { fin(-2, new Error('crypt_svc не ответил за 20 секунд')); }, 3000);
        }, 20000);
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

    function explain(err) {
        var m;
        if (/срок лицензии ист/.test(err)) {
            m = /до (\d+)/.exec(err);
            return 'срок лицензии истёк' + (m ? ' ' + dateText(m[1]) : '') + '.';
        }
        if (/не для этой машины/.test(err)) { return 'лицензия выписана на другой компьютер.'; }
        if (/подпись|формат лицензии|base64|лицензия пуста|нет подписи|payload/.test(err)) { return 'файл лицензии повреждён или не от этой программы.'; }
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
                if (/расшифровка не удалась|не \.crypt|read /.test(err)) {
                    fail('Анализ модели: файл «' + CRYPT + '» повреждён или от другой версии.' + NL + NL +
                        'Запустите двойным щелчком «Анализ_модели_UI.exe» из папки скрипта — он проверит и восстановит файлы.');
                    return;
                }
                fail('Анализ модели: не удалось запустить защищённый скрипт.' + NL + NL + (e ? e.message : (err || 'код ' + code)));
                return;
            }
            var m = /exp=(\d+)\s+dev=([0-9a-f]+)/.exec(err);
            if (m) { AN_LICENSE = { exp: Number(m[1]), dev: m[2] }; }
            trace('расшифровано ' + out.length + ' байт за ' + (Date.now() - t0) + ' мс' + (m ? ', лицензия до ' + dateText(m[1]) : ''));
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
