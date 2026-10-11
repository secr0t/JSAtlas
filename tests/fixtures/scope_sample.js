(!0).push([[], {
    "mod1": function (t, e, n) {
        var r = n("b775");
        const BASE = "/api";
        // ── 目标 API ──
        const list = function (a) {
            return r({url: BASE + "/org/list", method: "post", data: a});
        };
        const detail = function (a) {
            return r({url: BASE + "/org/detail", method: "post", data: a});
        };
        // ── 真 caller：同一 module，2 个调用点分属 2 个不同函数 ──
        function load() {
            return list({page: 1});
        }
        function loadAgain() {
            const p = {page: 2};
            return list(p);
        }
        function unusedCaller() {
            return detail({id: 3});
        }
        t.exports = {list: list, detail: detail};
    },
    "mod2": function (t, e, n) {
        var r = n("b775");
        // ── 同名 wrapper，但属于另一个 module（墙在这） ──
        const list = q => r({url: "/other/list", data: q});
        function go() {
            list(1);
            list(2);
            return list;
        }
        function wrongArity(x, y) {
            list(x, y);
        }
        t.exports = {list};
    },
    "mod3": function (t, e, n) {
        var r = n("b775");
        const spread = (...args) => r({url: "/rest/list", data: args});
        function one() {
            return spread(1);
        }
        function three() {
            return spread(1, 2, 3);
        }
        function four() {
            return spread(1, 2, 3, 4);
        }
        t.exports = {spread};
    }
}]);
