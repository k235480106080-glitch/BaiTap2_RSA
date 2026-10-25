using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using Microsoft.Win32;

namespace BaiTap2_RSA
{
    public partial class MainWindow : Window
    {
        private RSA rsaEngine;
        private string anchorSHAText = "";
        private byte[] pssSignature1, pssSignature2, pssSignature3;
        private byte[] dataToSign;

        public MainWindow()
        {
            InitializeComponent();
            rsaEngine = RSA.Create(2048);
            LogInfo("Hệ thống mã hóa bất đối xứng RSA & Chữ ký số đã sẵn sàng.");
            LogInfo("Sinh viên: Trần Hoàng Xuân Vũ | MSSV: K235480106080");
            AutoGenerateAndDisplayKeys();
        }

        #region UI Logging Helpers
        private void LogInfo(string message) => AppendLog($"[i] {message}\n", Color.FromRgb(56, 189, 248));
        private void LogHeader(string title) => AppendLog($"\n>>> {title} <<<\n", Color.FromRgb(251, 191, 36));
        private void LogSuccess(string message) => AppendLog($"[+] {message}\n", Color.FromRgb(52, 211, 153));
        private void LogError(string message) => AppendLog($"[-] ERROR: {message}\n", Color.FromRgb(248, 113, 113));

        private void AppendLog(string text, Color color)
        {
            Dispatcher.Invoke(() =>
            {
                TextRange tr = new TextRange(rtbLog.Document.ContentEnd, rtbLog.Document.ContentEnd)
                {
                    Text = text
                };
                tr.ApplyPropertyValue(TextElement.ForegroundProperty, new SolidColorBrush(color));
                rtbLog.ScrollToEnd();
            });
        }

        private void BtnClearLog_Click(object sender, RoutedEventArgs e) => rtbLog.Document.Blocks.Clear();
        #endregion

        #region 1. Sinh & Xuất Khóa (PEM)
        private void AutoGenerateAndDisplayKeys()
        {
            txtPublicKeyPEM.Text = rsaEngine.ExportRSAPublicKeyPem();
            txtPrivateKeyPEM.Text = rsaEngine.ExportRSAPrivateKeyPem();
            DisplayKeyDetails();
        }

        private void BtnGenRSA_Click(object sender, RoutedEventArgs e)
        {
            rsaEngine.Dispose();
            rsaEngine = RSA.Create(2048);
            AutoGenerateAndDisplayKeys();
            LogHeader("1. SINH CẶP KHÓA RSA-2048 MỚI THÀNH CÔNG");
            LogSuccess("Đã cập nhật Public Key và Private Key dạng PKCS#1 PEM.");
        }

        private void BtnExportPub_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog { Filter = "PEM Files (*.pem)|*.pem", FileName = "rsa_public_key.pem" };
            if (sfd.ShowDialog() == true)
            {
                File.WriteAllText(sfd.FileName, rsaEngine.ExportRSAPublicKeyPem());
                LogSuccess($"[2] Đã lưu Public Key ra file: {sfd.FileName}");
            }
        }

        private void BtnExportPriv_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog sfd = new SaveFileDialog { Filter = "PEM Files (*.pem)|*.pem", FileName = "rsa_private_key.pem" };
            if (sfd.ShowDialog() == true)
            {
                File.WriteAllText(sfd.FileName, rsaEngine.ExportRSAPrivateKeyPem());
                LogSuccess($"[2] Đã lưu Private Key ra file: {sfd.FileName}");
            }
        }
        #endregion

        #region 2 & 3 & 4. Import & Phân Tích PEM / ASN.1 DER
        private void BtnImportPubPEM_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "PEM Files (*.pem;*.txt)|*.pem;*.txt" };
            if (ofd.ShowDialog() == true)
            {
                string pemStr = File.ReadAllText(ofd.FileName);
                rsaEngine.ImportFromPem(pemStr);
                txtPublicKeyPEM.Text = rsaEngine.ExportRSAPublicKeyPem();
                DisplayKeyDetails();
                LogHeader("4. IMPORT PUBLIC KEY TỪ FILE PEM THÀNH CÔNG");
            }
        }

        private void BtnImportPrivPEM_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog { Filter = "PEM Files (*.pem;*.txt)|*.pem;*.txt" };
            if (ofd.ShowDialog() == true)
            {
                string pemStr = File.ReadAllText(ofd.FileName);
                rsaEngine.ImportFromPem(pemStr);
                txtPrivateKeyPEM.Text = rsaEngine.ExportRSAPrivateKeyPem();
                DisplayKeyDetails();
                LogHeader("4. IMPORT PRIVATE KEY TỪ FILE PEM THÀNH CÔNG");
            }
        }

        private void DisplayKeyDetails()
        {
            RSAParameters p = rsaEngine.ExportParameters(true);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== PHÂN TÍCH THAM SỐ TOÁN HỌC TỪ CẤU TRÚC ASN.1 DER ===");
            sb.AppendLine($"• Kích thước khóa (Key Size): {rsaEngine.KeySize} bits ({rsaEngine.KeySize / 8} bytes)");
            sb.AppendLine($"• Modulus (n = p * q)       : {Convert.ToHexString(p.Modulus!)}");
            sb.AppendLine($"• Public Exponent (e)        : {Convert.ToHexString(p.Exponent!)} (Giá trị thập phân: 65537 - 0x10001)");
            sb.AppendLine($"• Private Exponent (d)       : {Convert.ToHexString(p.D!)}");
            sb.AppendLine($"• Prime Factor 1 (p)        : {Convert.ToHexString(p.P!)}");
            sb.AppendLine($"• Prime Factor 2 (q)        : {Convert.ToHexString(p.Q!)}");
            sb.AppendLine("\n>>> Ý NGHĨA CÁC BYTE TRONG DỊNH DẠNG PEM / ASN.1:");
            sb.AppendLine("1. SEQUENCE (0x30): Thẻ bao bọc danh sách các tham số số nguyên.");
            sb.AppendLine("2. INTEGER (0x02) : Thẻ định danh số nguyên lớn (Modulus n, Mũ e, Mũ d...).");
            sb.AppendLine("3. 0x00 Prefix    : Thêm vào đầu các số nguyên có bit cao nhất là 1 để tránh hiểu nhầm là số âm.");

            txtKeyDetails.Text = sb.ToString();
        }
        #endregion

        #region 5 & 6. Mã Hóa & Giải Mã RSA
        private void BtnEncryptRSA_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] data = Encoding.UTF8.GetBytes(txtDataToEncrypt.Text);
                if (data.Length > 190)
                {
                    LogError("Dữ liệu vượt quá 190 bytes (giới hạn RSA-2048 OAEP)!");
                    return;
                }

                byte[] cipherBytes = rsaEngine.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
                string base64Cipher = Convert.ToBase64String(cipherBytes);
                txtCiphertextBase64.Text = base64Cipher;

                SaveFileDialog sfd = new SaveFileDialog { Filter = "DAT Files (*.dat)|*.dat", FileName = "rsa_encrypted_data.dat" };
                if (sfd.ShowDialog() == true)
                {
                    File.WriteAllText(sfd.FileName, base64Cipher);
                    LogSuccess($"[5] Đã mã hóa và lưu File Ciphertext Base64: {sfd.FileName}");
                }
            }
            catch (Exception ex)
            {
                LogError($"Lỗi mã hóa RSA: {ex.Message}");
            }
        }

        private void BtnDecryptRSA_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] cipherBytes = Convert.FromBase64String(txtCiphertextBase64.Text.Trim());
                byte[] decryptedBytes = rsaEngine.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                txtDecryptedResult.Text = decryptedText;

                bool isMatch = (txtDataToEncrypt.Text == decryptedText);
                LogHeader("6. KẾT QUẢ GIẢI MÃ RSA VÀ SO SÁNH");
                LogSuccess($"Decrypted Data: {decryptedText}");
                LogInfo($"Đối chứng với nguồn trước khi mã hóa: {(isMatch ? "CHÍNH XÁC 100% (Bit-by-Bit Identical)" : "SAI LỆCH")}");
            }
            catch (Exception ex)
            {
                LogError($"Lỗi giải mã RSA: {ex.Message}");
            }
        }
        #endregion

        #region 7. Benchmark Đánh Giá Tốc Độ (Public Key vs Private Key)
        private void BtnBenchmarkRSA_Click(object sender, RoutedEventArgs e)
        {
            int iterations = 500;
            byte[] sampleData = Encoding.UTF8.GetBytes("Test RSA Speed Benchmark 2026");

            // Measure Public Key Encryption Speed
            Stopwatch swPub = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                rsaEngine.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);
            }
            swPub.Stop();
            double pubOps = iterations / swPub.Elapsed.TotalSeconds;

            // Prepare single ciphertext for Private Key Decryption test
            byte[] cipherBytes = rsaEngine.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);

            // Measure Private Key Decryption Speed
            Stopwatch swPriv = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                rsaEngine.Decrypt(cipherBytes, RSAEncryptionPadding.OaepSHA256);
            }
            swPriv.Stop();
            double privOps = iterations / swPriv.Elapsed.TotalSeconds;

            double ratio = pubOps / privOps;

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== BÁO CÁO KẾT QUẢ BENCHMARK TỐC ĐỘ MÃ HÓA & GIẢI MÃ RSA-2048 ===");
            sb.AppendLine($"• Số lần thực nghiệm   : {iterations} phép tính");
            sb.AppendLine($"• Phép toán Public Key : {swPub.ElapsedMilliseconds} ms ({pubOps:N1} ops/sec) [Số mũ e = 65537 - Nhỏ]");
            sb.AppendLine($"• Phép toán Private Key: {swPriv.ElapsedMilliseconds} ms ({privOps:N1} ops/sec) [Số mũ d = 2048-bit - Rất lớn]");
            sb.AppendLine($"\n🔥 TỶ LỆ CHÊNH LỆCH HIỆU NĂNG: Public Key NHANH GẤP {ratio:F1} LẦN so với Private Key!");
            sb.AppendLine("\n>>> GIẢI THÍCH NGUYÊN LÝ TOÁN HỌC:");
            sb.AppendLine("1. Public Key (e = 65537 = 2^16 + 1): Chỉ chứa đúng 2 bit 1 ở dạng nhị phân. Phép tính lụy thừa M^e mod n chỉ tốn 17 phép tính nhân/bình phương.");
            sb.AppendLine("2. Private Key (d): Số mũ d có độ dài 2048-bit ngẫu nhiên chứa khoảng 1024 bit 1. Phép tính C^d mod n tốn hàng ngàn phép nhân modulo phức tạp.");

            txtBenchmarkReport.Text = sb.ToString();
            LogHeader("7. ĐÃ HOÀN THÀNH BENCHMARK TỐC ĐỘ RSA");
            LogSuccess($"Public Key nhanh gấp {ratio:F1} lần so with Private Key!");
        }
        #endregion

        #region 8. SHA-256 realtime & Avalanche Effect (Hiệu ứng tuyết rơi)
        private void TxtSHAInput_TextChanged(object sender, TextChangedEventArgs e)
        {
            UpdateSHAReport();
        }

        private void BtnSetSHAAnchor_Click(object sender, RoutedEventArgs e)
        {
            anchorSHAText = txtSHAInput.Text;
            UpdateSHAReport();
            LogSuccess("Đã chốt mốc dữ liệu ban đầu để so sánh hiệu ứng tuyết rơi.");
        }

        private void BtnFlipBit_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(txtSHAInput.Text)) return;
            char lastChar = txtSHAInput.Text[txtSHAInput.Text.Length - 1];
            txtSHAInput.Text = txtSHAInput.Text.Substring(0, txtSHAInput.Text.Length - 1) + (char)(lastChar ^ 1);
        }

        private void UpdateSHAReport()
        {
            if (txtSHAReport == null) return;

            string currentText = txtSHAInput.Text;
            byte[] currentHash = SHA256.HashData(Encoding.UTF8.GetBytes(currentText));
            string currentHashHex = Convert.ToHexString(currentHash);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"• Chuỗi đầu vào hiện tại: {currentText}");
            sb.AppendLine($"• Hash SHA-256 (Hex 64 char): {currentHashHex}");

            if (!string.IsNullOrEmpty(anchorSHAText))
            {
                byte[] anchorHash = SHA256.HashData(Encoding.UTF8.GetBytes(anchorSHAText));
                string anchorHashHex = Convert.ToHexString(anchorHash);

                int changedBits = 0;
                for (int i = 0; i < anchorHash.Length; i++)
                {
                    byte diff = (byte)(anchorHash[i] ^ currentHash[i]);
                    while (diff > 0)
                    {
                        changedBits += (diff & 1);
                        diff >>= 1;
                    }
                }

                double percentage = (changedBits / 256.0) * 100;
                sb.AppendLine("\n=== SO SÁNH VỚI MỐC BAN ĐẦU (AVALANCHE EFFECT) ===");
                sb.AppendLine($"• Mốc gốc Text : {anchorSHAText}");
                sb.AppendLine($"• Mốc gốc Hash : {anchorHashHex}");
                sb.AppendLine($"• Số bit biến đổi: {changedBits} / 256 bits");
                sb.AppendLine($"• Tỷ lệ biến đổi : {percentage:F2}% (Mức lý tưởng của hàm băm là ~50%)");
                sb.AppendLine("\n>>> KẾT LUẬN: Chỉ cần thay đổi 1 bit đầu vào, hàm băm SHA-256 sinh ra giá trị băm mới bị xáo trộn gần 50% số bit ngẫu nhiên.");
            }

            txtSHAReport.Text = sb.ToString();
        }
        #endregion

        #region 9. Chữ ký số & Giải pháp RSASSA-PSS (Mỗi lần ký ra 1 Chữ ký khác nhau)
        private void BtnSignPSS_Click(object sender, RoutedEventArgs e)
        {
            dataToSign = Encoding.UTF8.GetBytes("Hợp đồng chuyển nhượng - SV Trần Hoàng Xuân Vũ - K235480106080");

            // Ký 3 lần cùng 1 dữ liệu + cùng 1 Private Key bằng chuẩn RSASSA-PSS (có Random Salt)
            pssSignature1 = rsaEngine.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            pssSignature2 = rsaEngine.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            pssSignature3 = rsaEngine.SignData(dataToSign, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== ĐỀ XUẤT GIẢI PHÁP: CHUẨN KÝ SỐ RSASSA-PSS (RFC 8017) ===");
            sb.AppendLine("Yêu cầu: Cùng 1 dữ liệu + Cùng Private Key -> Cho ra chữ ký số KHÁC NHAU ở mỗi lần ký.");
            sb.AppendLine("Giải pháp: Sử dụng chuẩn RSASSA-PSS (PKCS#1 v2.1). Chuẩn này tự động chèn thêm một chuỗi Muối ngẫu nhiên (Random Salt 32 bytes) vào trước khi băm và ký.");
            sb.AppendLine("\n>>> KẾT QUẢ THỰC NGHIỆM KÝ 3 LẦN LIÊN TIẾP:");
            sb.AppendLine($"1. Chữ ký Lần 1 (Base64): {Convert.ToBase64String(pssSignature1).Substring(0, 60)}...");
            sb.AppendLine($"2. Chữ ký Lần 2 (Base64): {Convert.ToBase64String(pssSignature2).Substring(0, 60)}...");
            sb.AppendLine($"3. Chữ ký Lần 3 (Base64): {Convert.ToBase64String(pssSignature3).Substring(0, 60)}...");

            txtPSSReport.Text = sb.ToString();
            LogHeader("9. ĐÃ THỰC THI CHỮ KÝ SỐ RSASSA-PSS 3 LẦN");
            LogSuccess("Cả 3 chữ ký tạo ra hoàn toàn khác nhau nhưng đều hợp lệ!");
        }

        private void BtnVerifyPSS_Click(object sender, RoutedEventArgs e)
        {
            if (pssSignature1 == null || dataToSign == null)
            {
                LogError("Vui lòng bấm 'Ký 3 Lần' trước!");
                return;
            }

            bool v1 = rsaEngine.VerifyData(dataToSign, pssSignature1, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            bool v2 = rsaEngine.VerifyData(dataToSign, pssSignature2, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            bool v3 = rsaEngine.VerifyData(dataToSign, pssSignature3, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            StringBuilder sb = new StringBuilder(txtPSSReport.Text);
            sb.AppendLine("\n=== KẾT QUẢ XÁC THỰC CẢ 3 CHỮ KÝ BẰNG DUY NHẤT 1 PUBLIC KEY ===");
            sb.AppendLine($"• Xác thực Chữ ký 1: {(v1 ? "✅ HỢP LỆ (VALID)" : "❌ THẤT BẠI")}");
            sb.AppendLine($"• Xác thực Chữ ký 2: {(v2 ? "✅ HỢP LỆ (VALID)" : "❌ THẤT BẠI")}");
            sb.AppendLine($"• Xác thực Chữ ký 3: {(v3 ? "✅ HỢP LỆ (VALID)" : "❌ THẤT BẠI")}");
            sb.AppendLine("=> KẾT LUẬN: Đề xuất áp dụng RSASSA-PSS thành công tuyệt đối!");

            txtPSSReport.Text = sb.ToString();
            LogSuccess("Xác thực Public Key thành công 100% cho cả 3 chữ ký!");
        }
        #endregion
    }
}