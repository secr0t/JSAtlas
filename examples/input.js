/*!
 * examples/input.js —— JSAtlas 示例输入
 *
 * 刻意覆盖了 JSAtlas 首期四类分析能力的触发形态：
 *   1. API 路径 + 请求方法（surface）
 *   2. query / path / body 参数（point）
 *   3. 上下文恢复：wrapper 函数与调用点（context）
 *   4. 敏感信息与配置线索（intelligence）
 *
 * 文件里的所有"密钥""内网地址"都是编造的示例值，不含真实凭证。
 */

(function () {
  'use strict';

  // ---- 1. 环境配置线索 ----
  var API_HOST = 'https://api.example.com';
  process.env.NODE_ENV === "development";
  axios.defaults.baseURL = 'https://api.example.com/v1';

  var CONFIG = {
    appId: 'wxa1b2c3d4e5f6a7b8',
    appSecret: '9f8e7d6c5b4a39281706f5e4d3c2b1a0',
    aesKey: 'A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6'
  };

  // ---- 2. 带参数的接口 ----
  function fetchUserList(page, size) {
    return axios.get('/api/v1/users', {
      params: {
        page: page,
        size: size,
        keyword: ''
      }
    });
  }

  function createOrder(payload) {
    return axios.post('/api/v1/order/create', {
      data: {
        goodsId: payload.goodsId,
        quantity: payload.quantity,
        addressId: payload.addressId
      }
    });
  }

  // 模板路径 + 拼接
  function deleteItem(id) {
    return request({
      url: '/api/v1/items/' + id + '/delete',
      method: 'DELETE'
    });
  }

  // query 串写在路径里
  function search(kw) {
    return fetch('/api/v1/search?keyword=' + kw + '&pageSize=20');
  }

  // ---- 3. 敏感信息（示例值，均为编造） ----
  var awsAccessKeyId = 'AKIAEXAMPLE1EXAMPLE2';
  var jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  var dbUrl = 'jdbc:mysql://10.20.30.40:3306/prod?useSSL=false';
  var adminPhone = '13800138000';
  var opsEmail = 'ops@example.com';

  // ---- 4. 认证与调试线索 ----
  var headers = {
    'Authorization': 'Bearer ' + jwtToken,
    'X-Access-Token': jwtToken
  };
  var DEBUG = true;
  axios.defaults.withCredentials = true;

  // ---- 5. 调用点 ----
  function onPageLoad() {
    fetchUserList(1, 20);
  }

  function onSubmit(data) {
    createOrder(data);
  }

  window.__app = {
    fetchUserList: fetchUserList,
    createOrder: createOrder,
    deleteItem: deleteItem,
    search: search,
    onPageLoad: onPageLoad,
    onSubmit: onSubmit
  };
})();
