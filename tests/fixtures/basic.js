const BASE = "/api";
axios.defaults.baseURL = "https://api.example.com";
function getUser(id) {
  return axios.get(BASE + "/user/detail", { params: { id: id, verbose: 1 } });
}
function create(data) {
  return axios.post("/api/user/create", { data: { name: data.name, age: data.age } });
}
const ak = "AKIAEXAMPLE1EXAMPLE2";
const db = "jdbc:mysql://10.0.0.5:3306/app";
const ip = "192.168.1.10";
// 下面这条留给计算式打分链路（熵/分词）：正则链路移除后，
// JDBC / 内网 IP 这类结构化线索不再由 JSAtlas 判定，样本必须有一条能被"算"出来的。
const appSecret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
