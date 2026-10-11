// 供统计学密钥打分链路使用的样本。
// 这里的串没有任何先验类型（不是手机号/邮箱/IP/JDBC），
// 只有"高熵 + 不像英文单词"这一个特征，正好对应 JScanner2 SecretMathScorer 的判定面。
const appSecret = "9f8e7d6c5b4a39281706f5e4d3c2b1a0";
const aesKey = "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6";
const signature = "d2f8c1a94e7b6035f1d8c7a2b9e4f630";

function boot() {
  return register({ Secret: appSecret, Key: aesKey, Sig: signature });
}
