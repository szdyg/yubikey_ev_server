using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace yubikey_ev_server
{
    // Token: 0x02000033 RID: 51
    internal class CodeSign
    {
        // Token: 0x060001D0 RID: 464
        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSign(IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, string pwszHttpTimeStamp, IntPtr psRequest, IntPtr pSipData);

        // Token: 0x060001D1 RID: 465
        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerSignEx(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, string pwszHttpTimeStamp, IntPtr psRequest, IntPtr pSipData, out CodeSign.SIGNER_CONTEXT ppSignerContext);

        // Token: 0x060001D2 RID: 466
        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStamp(IntPtr pSubjectInfo, string pwszHttpTimeStamp, IntPtr psRequest, IntPtr pSipData);

        // Token: 0x060001D3 RID: 467
        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx(uint dwFlags, IntPtr pSubjectInfo, string pwszHttpTimeStamp, IntPtr psRequest, IntPtr pSipData, out CodeSign.SIGNER_CONTEXT ppSignerContext);

        // Token: 0x060001D4 RID: 468
        [DllImport("Mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int SignerTimeStampEx2(uint dwFlags, IntPtr pSubjectInfo, string pwszHttpTimeStamp, IntPtr pszTimeStampAlgorithmOid, IntPtr psRequest, IntPtr pSipData, out IntPtr ppSignerContext);

        // Token: 0x060001D5 RID: 469
        [DllImport("Crypt32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CertCreateCertificateContext(int dwCertEncodingType, byte[] pbCertEncoded, int cbCertEncoded);

        // Token: 0x060001D6 RID: 470 RVA: 0x0001448C File Offset: 0x0001268C
        private static IntPtr CreateSignerSubjectInfo(string fileName)
        {
            CodeSign.SIGNER_SUBJECT_INFO signer_SUBJECT_INFO = new CodeSign.SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_SUBJECT_INFO)),
                pdwIndex = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(uint))),
                dwSubjectChoice = 1U,
                Union = new CodeSign.SIGNER_SUBJECT_INFO.SubjectChoiceUnion
                {
                    pSignerFileInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CodeSign.SIGNER_FILE_INFO)))
                }
            };
            Marshal.StructureToPtr<int>(0, signer_SUBJECT_INFO.pdwIndex, false);
            IntPtr pwszFileName = Marshal.StringToHGlobalUni(fileName);
            Marshal.StructureToPtr<CodeSign.SIGNER_FILE_INFO>(new CodeSign.SIGNER_FILE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_FILE_INFO)),
                pwszFileName = pwszFileName,
                hFile = IntPtr.Zero
            }, signer_SUBJECT_INFO.Union.pSignerFileInfo, false);
            IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CodeSign.SIGNER_SUBJECT_INFO>(signer_SUBJECT_INFO));
            Marshal.StructureToPtr<CodeSign.SIGNER_SUBJECT_INFO>(signer_SUBJECT_INFO, intPtr, false);
            return intPtr;
        }

        // Token: 0x060001D7 RID: 471 RVA: 0x00014578 File Offset: 0x00012778
        private static X509Certificate2 FindCertByThumbprint(string thumbprint)
        {
            X509Certificate2 result;
            try
            {
                thumbprint.Replace(" ", string.Empty).ToUpperInvariant();
                X509Certificate2Collection x509Certificate2Collection = CodeSign.FindInStores(new X509Store[]
                {
                    new X509Store(StoreName.My, StoreLocation.CurrentUser),
                    new X509Store(StoreName.My, StoreLocation.LocalMachine)
                }, X509FindType.FindByThumbprint, thumbprint, false);
                if (x509Certificate2Collection == null || x509Certificate2Collection.Count.Equals(0))
                {
                    result = null;
                }
                else
                {
                    result = x509Certificate2Collection[0];
                }
            }
            catch
            {
                throw new Exception("The specified thumbprint did not match any certificate!");
            }
            return result;
        }

        // Token: 0x060001D8 RID: 472 RVA: 0x00014600 File Offset: 0x00012800
        private static IntPtr CreateSignerCert(X509Certificate2 cert)
        {
            CodeSign.SIGNER_CERT signer_CERT = new CodeSign.SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT)),
                dwCertChoice = 2U,
                Union = new CodeSign.SIGNER_CERT.SignerCertUnion
                {
                    pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT_STORE_INFO)))
                },
                hwnd = IntPtr.Zero
            };
            byte[] rawCertData = cert.GetRawCertData();
            IntPtr pSigningCert = CodeSign.CertCreateCertificateContext(65537, rawCertData, rawCertData.Length);
            Marshal.StructureToPtr<CodeSign.SIGNER_CERT_STORE_INFO>(new CodeSign.SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT_STORE_INFO)),
                pSigningCert = pSigningCert,
                dwCertPolicy = 2U,
                hCertStore = IntPtr.Zero
            }, signer_CERT.Union.pCertStoreInfo, false);
            IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CodeSign.SIGNER_CERT>(signer_CERT));
            Marshal.StructureToPtr<CodeSign.SIGNER_CERT>(signer_CERT, intPtr, false);
            return intPtr;
        }

        // Token: 0x060001D9 RID: 473 RVA: 0x000146E8 File Offset: 0x000128E8
        private static IntPtr CreateSignerCert(string thumbprint)
        {
            CodeSign.SIGNER_CERT signer_CERT = new CodeSign.SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT)),
                dwCertChoice = 2U,
                Union = new CodeSign.SIGNER_CERT.SignerCertUnion
                {
                    pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT_STORE_INFO)))
                },
                hwnd = IntPtr.Zero
            };
            byte[] rawCertData = CodeSign.FindCertByThumbprint(thumbprint).GetRawCertData();
            IntPtr pSigningCert = CodeSign.CertCreateCertificateContext(65537, rawCertData, rawCertData.Length);
            Marshal.StructureToPtr<CodeSign.SIGNER_CERT_STORE_INFO>(new CodeSign.SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_CERT_STORE_INFO)),
                pSigningCert = pSigningCert,
                dwCertPolicy = 2U,
                hCertStore = IntPtr.Zero
            }, signer_CERT.Union.pCertStoreInfo, false);
            IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CodeSign.SIGNER_CERT>(signer_CERT));
            Marshal.StructureToPtr<CodeSign.SIGNER_CERT>(signer_CERT, intPtr, false);
            return intPtr;
        }

        // Token: 0x060001DA RID: 474 RVA: 0x000147D4 File Offset: 0x000129D4
        private static IntPtr CreateSignerSignatureInfo()
        {
            CodeSign.SIGNER_SIGNATURE_INFO structure = new CodeSign.SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_SIGNATURE_INFO)),
                algidHash = 32780U,
                dwAttrChoice = 0U,
                pAttrAuthCode = IntPtr.Zero,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero
            };
            IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CodeSign.SIGNER_SIGNATURE_INFO>(structure));
            Marshal.StructureToPtr<CodeSign.SIGNER_SIGNATURE_INFO>(structure, intPtr, false);
            return intPtr;
        }

        // Token: 0x060001DB RID: 475 RVA: 0x0001484C File Offset: 0x00012A4C
        private static IntPtr GetProviderInfo(X509Certificate2 cert)
        {
            if (cert == null || !cert.HasPrivateKey)
            {
                return IntPtr.Zero;
            }
            ICspAsymmetricAlgorithm cspAsymmetricAlgorithm = (ICspAsymmetricAlgorithm)cert.PrivateKey;
            if (cspAsymmetricAlgorithm == null)
            {
                return IntPtr.Zero;
            }
            CodeSign.SIGNER_PROVIDER_INFO structure = new CodeSign.SIGNER_PROVIDER_INFO
            {
                cbSize = (uint)Marshal.SizeOf(typeof(CodeSign.SIGNER_PROVIDER_INFO)),
                pwszProviderName = Marshal.StringToHGlobalUni(cspAsymmetricAlgorithm.CspKeyContainerInfo.ProviderName),
                dwProviderType = (uint)cspAsymmetricAlgorithm.CspKeyContainerInfo.ProviderType,
                dwPvkChoice = 2U,
                Union = new CodeSign.SIGNER_PROVIDER_INFO.SignerProviderUnion
                {
                    pwszKeyContainer = Marshal.StringToHGlobalUni(cspAsymmetricAlgorithm.CspKeyContainerInfo.KeyContainerName)
                }
            };
            IntPtr intPtr = Marshal.AllocHGlobal(Marshal.SizeOf<CodeSign.SIGNER_PROVIDER_INFO>(structure));
            Marshal.StructureToPtr<CodeSign.SIGNER_PROVIDER_INFO>(structure, intPtr, false);
            return intPtr;
        }

        // Token: 0x060001DC RID: 476 RVA: 0x0001490A File Offset: 0x00012B0A
        private static void SignCode(IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo)
        {
            if (CodeSign.SignerSign(pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, null, IntPtr.Zero, IntPtr.Zero) != 0)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }

        // Token: 0x060001DD RID: 477 RVA: 0x0001492C File Offset: 0x00012B2C
        private static void SignCode(uint dwFlags, IntPtr pSubjectInfo, IntPtr pSignerCert, IntPtr pSignatureInfo, IntPtr pProviderInfo, out CodeSign.SIGNER_CONTEXT signerContext)
        {
            if (CodeSign.SignerSignEx(dwFlags, pSubjectInfo, pSignerCert, pSignatureInfo, pProviderInfo, null, IntPtr.Zero, IntPtr.Zero, out signerContext) != 0)
            {
                Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
            }
        }

        // Token: 0x060001DE RID: 478 RVA: 0x00014960 File Offset: 0x00012B60
        private static void TimeStampSignedCode(IntPtr pSubjectInfo, string timestampUrl)
        {
            IntPtr intPtr;
            if (CodeSign.SignerTimeStampEx2(2U, pSubjectInfo, timestampUrl, Marshal.StringToHGlobalAnsi("2.16.840.1.101.3.4.2.1"), IntPtr.Zero, IntPtr.Zero, out intPtr) != 0)
            {
                throw new Exception("Failed to timestamp signed file using the selected server!");
            }
        }

        // Token: 0x060001DF RID: 479 RVA: 0x00014998 File Offset: 0x00012B98
        private static string ErrorFromException(Exception ex)
        {
            string result = string.Empty;
            if (ex == null)
            {
                return result;
            }
            uint hrforException = (uint)Marshal.GetHRForException(ex);
            result = ex.Message;
            if (hrforException <= 2148081668U)
            {
                if (hrforException <= 2147942486U)
                {
                    if (hrforException == 2147942406U)
                    {
                        return "Please make sure the destination file is not in use!";
                    }
                    if (hrforException != 2147942486U)
                    {
                        return result;
                    }
                    return "Please make sure the specified password is correct!";
                }
                else if (hrforException != 2147942593U)
                {
                    if (hrforException != 2148081668U)
                    {
                        return result;
                    }
                    goto IL_A1;
                }
            }
            else if (hrforException <= 2148081673U)
            {
                if (hrforException == 2148081670U)
                {
                    return "Please make sure the private key can be accessed!";
                }
                if (hrforException != 2148081673U)
                {
                    return result;
                }
                return "The specified certificate does not appear to be valid!";
            }
            else if (hrforException != 2148204547U)
            {
                if (hrforException != 2148204810U)
                {
                    return result;
                }
                goto IL_A1;
            }
            return "The input file does not seem to be suitable for signing!";
        IL_A1:
            result = "Please make sure the certificate is not expired!";
            return result;
        }

        // Token: 0x060001E0 RID: 480 RVA: 0x00014A50 File Offset: 0x00012C50
        public static X509Certificate2Collection FindInStores(X509Store[] locations, X509FindType findCriteria, object findValue, bool validOnly)
        {
            X509Certificate2Collection x509Certificate2Collection = new X509Certificate2Collection();
            foreach (X509Store x509Store in locations)
            {
                x509Store.Open(OpenFlags.OpenExistingOnly);
                x509Certificate2Collection.AddRange(x509Store.Certificates.Find(findCriteria, findValue, validOnly));
                x509Store.Close();
            }
            return x509Certificate2Collection;
        }

        // Token: 0x060001E1 RID: 481 RVA: 0x00014A9C File Offset: 0x00012C9C
        public static bool Sign(string fileName, string certPath, string certPassword, string timestampUrl, out string winError)
        {
            IntPtr intPtr = IntPtr.Zero;
            IntPtr intPtr2 = IntPtr.Zero;
            IntPtr intPtr3 = IntPtr.Zero;
            IntPtr intPtr4 = IntPtr.Zero;
            try
            {
                X509Certificate2 cert = new X509Certificate2(certPath, certPassword);
                intPtr = CodeSign.CreateSignerCert(cert);
                intPtr2 = CodeSign.CreateSignerSubjectInfo(fileName);
                intPtr3 = CodeSign.CreateSignerSignatureInfo();
                intPtr4 = CodeSign.GetProviderInfo(cert);
                CodeSign.SIGNER_CONTEXT signer_CONTEXT;
                CodeSign.SignCode(0U, intPtr2, intPtr, intPtr3, intPtr4, out signer_CONTEXT);
                if (!string.IsNullOrWhiteSpace(timestampUrl))
                {
                    CodeSign.TimeStampSignedCode(intPtr2, timestampUrl);
                }
                winError = string.Empty;
            }
            catch (Exception ex)
            {
                winError = CodeSign.ErrorFromException(ex);
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr, typeof(CodeSign.SIGNER_CERT));
                }
                if (intPtr2 != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr2, typeof(CodeSign.SIGNER_SUBJECT_INFO));
                }
                if (intPtr3 != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr3, typeof(CodeSign.SIGNER_SIGNATURE_INFO));
                }
                if (intPtr4 != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr3, typeof(CodeSign.SIGNER_PROVIDER_INFO));
                }
            }
            return string.IsNullOrWhiteSpace(winError);
        }

        // Token: 0x060001E2 RID: 482 RVA: 0x00014BB4 File Offset: 0x00012DB4
        public static bool Sign(string fileName, string thumbprint, string timestampUrl, out string winError)
        {
            IntPtr intPtr = IntPtr.Zero;
            IntPtr intPtr2 = IntPtr.Zero;
            IntPtr intPtr3 = IntPtr.Zero;
            IntPtr zero = IntPtr.Zero;
            try
            {
                intPtr = CodeSign.CreateSignerCert(thumbprint);
                intPtr2 = CodeSign.CreateSignerSubjectInfo(fileName);
                intPtr3 = CodeSign.CreateSignerSignatureInfo();
                CodeSign.SignCode(intPtr2, intPtr, intPtr3, zero);
                if (!string.IsNullOrWhiteSpace(timestampUrl))
                {
                    CodeSign.TimeStampSignedCode(intPtr2, timestampUrl);
                }
                winError = string.Empty;
            }
            catch (Exception ex)
            {
                winError = CodeSign.ErrorFromException(ex);
            }
            finally
            {
                if (intPtr != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr, typeof(CodeSign.SIGNER_CERT));
                }
                if (intPtr2 != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr2, typeof(CodeSign.SIGNER_SUBJECT_INFO));
                }
                if (intPtr3 != IntPtr.Zero)
                {
                    Marshal.DestroyStructure(intPtr3, typeof(CodeSign.SIGNER_SIGNATURE_INFO));
                }
            }
            return string.IsNullOrWhiteSpace(winError);
        }

        // Token: 0x02000086 RID: 134
        private struct SIGNER_SUBJECT_INFO
        {
            // Token: 0x040004E3 RID: 1251
            public uint cbSize;

            // Token: 0x040004E4 RID: 1252
            public IntPtr pdwIndex;

            // Token: 0x040004E5 RID: 1253
            public uint dwSubjectChoice;

            // Token: 0x040004E6 RID: 1254
            public CodeSign.SIGNER_SUBJECT_INFO.SubjectChoiceUnion Union;

            // Token: 0x020000A7 RID: 167
            [StructLayout(LayoutKind.Explicit)]
            internal struct SubjectChoiceUnion
            {
                // Token: 0x04000541 RID: 1345
                [FieldOffset(0)]
                public IntPtr pSignerFileInfo;

                // Token: 0x04000542 RID: 1346
                [FieldOffset(0)]
                public IntPtr pSignerBlobInfo;
            }
        }

        // Token: 0x02000087 RID: 135
        private struct SIGNER_CERT
        {
            // Token: 0x040004E7 RID: 1255
            public uint cbSize;

            // Token: 0x040004E8 RID: 1256
            public uint dwCertChoice;

            // Token: 0x040004E9 RID: 1257
            public CodeSign.SIGNER_CERT.SignerCertUnion Union;

            // Token: 0x040004EA RID: 1258
            public IntPtr hwnd;

            // Token: 0x020000A8 RID: 168
            [StructLayout(LayoutKind.Explicit)]
            internal struct SignerCertUnion
            {
                // Token: 0x04000543 RID: 1347
                [FieldOffset(0)]
                public IntPtr pwszSpcFile;

                // Token: 0x04000544 RID: 1348
                [FieldOffset(0)]
                public IntPtr pCertStoreInfo;

                // Token: 0x04000545 RID: 1349
                [FieldOffset(0)]
                public IntPtr pSpcChainInfo;
            }
        }

        // Token: 0x02000088 RID: 136
        private struct SIGNER_SIGNATURE_INFO
        {
            // Token: 0x040004EB RID: 1259
            public uint cbSize;

            // Token: 0x040004EC RID: 1260
            public uint algidHash;

            // Token: 0x040004ED RID: 1261
            public uint dwAttrChoice;

            // Token: 0x040004EE RID: 1262
            public IntPtr pAttrAuthCode;

            // Token: 0x040004EF RID: 1263
            public IntPtr psAuthenticated;

            // Token: 0x040004F0 RID: 1264
            public IntPtr psUnauthenticated;
        }

        // Token: 0x02000089 RID: 137
        private struct SIGNER_FILE_INFO
        {
            // Token: 0x040004F1 RID: 1265
            public uint cbSize;

            // Token: 0x040004F2 RID: 1266
            public IntPtr pwszFileName;

            // Token: 0x040004F3 RID: 1267
            public IntPtr hFile;
        }

        // Token: 0x0200008A RID: 138
        private struct SIGNER_CERT_STORE_INFO
        {
            // Token: 0x040004F4 RID: 1268
            public uint cbSize;

            // Token: 0x040004F5 RID: 1269
            public IntPtr pSigningCert;

            // Token: 0x040004F6 RID: 1270
            public uint dwCertPolicy;

            // Token: 0x040004F7 RID: 1271
            public IntPtr hCertStore;
        }

        // Token: 0x0200008B RID: 139
        private struct SIGNER_CONTEXT
        {
            // Token: 0x040004F8 RID: 1272
            public uint cbSize;

            // Token: 0x040004F9 RID: 1273
            public uint cbBlob;

            // Token: 0x040004FA RID: 1274
            public IntPtr pbBlob;
        }

        // Token: 0x0200008C RID: 140
        private struct SIGNER_PROVIDER_INFO
        {
            // Token: 0x040004FB RID: 1275
            public uint cbSize;

            // Token: 0x040004FC RID: 1276
            public IntPtr pwszProviderName;

            // Token: 0x040004FD RID: 1277
            public uint dwProviderType;

            // Token: 0x040004FE RID: 1278
            public uint dwKeySpec;

            // Token: 0x040004FF RID: 1279
            public uint dwPvkChoice;

            // Token: 0x04000500 RID: 1280
            public CodeSign.SIGNER_PROVIDER_INFO.SignerProviderUnion Union;

            // Token: 0x020000A9 RID: 169
            [StructLayout(LayoutKind.Explicit)]
            internal struct SignerProviderUnion
            {
                // Token: 0x04000546 RID: 1350
                [FieldOffset(0)]
                public IntPtr pwszPvkFileName;

                // Token: 0x04000547 RID: 1351
                [FieldOffset(0)]
                public IntPtr pwszKeyContainer;
            }
        }
    }
}
