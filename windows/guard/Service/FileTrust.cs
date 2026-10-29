using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Cortmed.Guard
{
    // Bir calisan surecin baslangic puanini imza ve konuma gore belirler.
    // Imza: once gomulu imza (WinVerifyTrust, dosya), olmazsa katalog imzasi
    // (CryptCATAdmin ile hash -> katalog -> WinVerifyTrust, katalog).
    public static class FileTrust
    {
        // %SystemRoot% altinda standart kullanicilarin dosya olusturup calistirabildigi bilinen klasorler:
        // buradaki imzali dosya konum bonusu almaz (Windows klasoru oneki tek basina guven saymaz).
        static readonly string[] UserWritableWindowsDirs =
        {
            @"{System32}\spool\drivers\color", @"{System32}\Tasks", @"{System32}\com\dmp", @"{System32}\FxsTmp",
            @"{System32}\Microsoft\Crypto\RSA\MachineKeys", @"{System32}\Tasks_Migrated",
            @"{SysWOW64}\Tasks", @"{SysWOW64}\com\dmp", @"{SysWOW64}\FxsTmp",
            @"{Windows}\Tasks", @"{Windows}\Temp", @"{Windows}\tracing", @"{Windows}\Registration\CRMLog"
        };

        static bool InUserWritableWindowsDir(string full)
        {
            var kf = KnownFolders.Current;
            string dir = Path.GetDirectoryName(full) ?? "";
            // klasorun kendisi ya da herhangi bir alt klasoru
            while (!string.IsNullOrEmpty(dir))
            {
                if (PathRules.MatchesAny(UserWritableWindowsDirs, dir, kf)) return true;
                string up = Path.GetDirectoryName(dir);
                if (up == dir) break;
                dir = up;
            }
            return false;
        }

        static readonly Regex UserFolder = new Regex(
            @"\\Users\\(Public\\|[^\\]+\\(Downloads|Desktop|AppData)\\|[^\\]+\\OneDrive[^\\]*\\(Desktop|Downloads|Documents|Belgeler|Masaüstü)\\)|\\Windows\\Temp\\",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        public static int BaseScore(string imagePath, BehaviorRules r)
        {
            try
            {
                if (string.IsNullOrEmpty(imagePath) || !File.Exists(imagePath)) return 15;
                string full = Path.GetFullPath(imagePath);
                return LocationScore(full, IsValidlySigned(full), r);
            }
            catch { return 15; }
        }

        // Saf karar: imzali -> guvenilir konumda ve kullanici klasoru degilse bonus, aksi 0;
        // imzasiz -> 15, kullanici klasorunde 30.
        internal static int LocationScore(string fullPath, bool signed, BehaviorRules r)
        {
            bool user = UserFolder.IsMatch(fullPath);
            if (signed) return IsTrustedLocation(fullPath) && !user && !InUserWritableWindowsDir(fullPath) ? r.TrustedLocationBonus : 0;
            return user ? 30 : 15;
        }

        static bool IsTrustedLocation(string full)
        {
            string[] roots =
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetEnvironmentVariable("SystemRoot")
            };
            foreach (string root in roots)
            {
                if (string.IsNullOrEmpty(root)) continue;
                string prefix = root.TrimEnd('\\') + "\\";
                if (full.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return true;
            }
            return false;
        }

        public static bool IsValidlySigned(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return false;
                if (VerifyFile(path)) return true;
                return FindCatalog(path) != null;
            }
            catch { return false; }
        }

        // Imzalayan sertifikanin ortak adi (CN). Gomulu imza yoksa katalog dosyasinin imzacisi
        // (Windows dosyalari icin "Microsoft Windows"). Belirlenemezse "".
        public static string Publisher(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return "";
                string name = SignerName(path);
                if (name.Length > 0) return name;
                string cat = FindCatalog(path);
                return cat == null ? "" : SignerName(cat);
            }
            catch { return ""; }
        }

        static string SignerName(string path)
        {
            try
            {
                var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
                return cert.GetNameInfo(X509NameType.SimpleName, false) ?? "";
            }
            catch { return ""; }
        }

        // ---- WinVerifyTrust ----

        static readonly Guid ActionGenericVerifyV2 = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        const uint WTD_UI_NONE = 2;
        const uint WTD_REVOKE_NONE = 0;
        const uint WTD_CHOICE_FILE = 1;
        const uint WTD_CHOICE_CATALOG = 2;
        const uint WTD_STATEACTION_VERIFY = 1;
        const uint WTD_STATEACTION_CLOSE = 2;
        const uint WTD_REVOCATION_CHECK_NONE = 0x10;
        const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_FILE_INFO
        {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct WINTRUST_CATALOG_INFO
        {
            public uint cbStruct;
            public uint dwCatalogVersion;
            public string pcwszCatalogFilePath;
            public string pcwszMemberTag;
            public string pcwszMemberFilePath;
            public IntPtr hMemberFile;
            public IntPtr pbCalculatedFileHash;
            public uint cbCalculatedFileHash;
            public IntPtr pcCatalogContext;
            public IntPtr hCatAdmin;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct WINTRUST_DATA
        {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pInfo;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
        static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

        static bool VerifyFile(string path)
        {
            var fi = new WINTRUST_FILE_INFO();
            fi.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
            fi.pcwszFilePath = path;
            return Verify(fi, WTD_CHOICE_FILE);
        }

        static bool VerifyCatalog(string catalogPath, string memberTag, string memberPath, byte[] hash, IntPtr hCatAdmin)
        {
            IntPtr hashPtr = Marshal.AllocHGlobal(hash.Length);
            try
            {
                Marshal.Copy(hash, 0, hashPtr, hash.Length);
                var ci = new WINTRUST_CATALOG_INFO();
                ci.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_CATALOG_INFO));
                ci.pcwszCatalogFilePath = catalogPath;
                ci.pcwszMemberTag = memberTag;
                ci.pcwszMemberFilePath = memberPath;
                ci.pbCalculatedFileHash = hashPtr;
                ci.cbCalculatedFileHash = (uint)hash.Length;
                ci.hCatAdmin = hCatAdmin;
                return Verify(ci, WTD_CHOICE_CATALOG);
            }
            finally { Marshal.FreeHGlobal(hashPtr); }
        }

        static bool Verify(object info, uint choice)
        {
            IntPtr infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf(info.GetType()));
            Marshal.StructureToPtr(info, infoPtr, false);
            var data = new WINTRUST_DATA();
            data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = choice;
            data.pInfo = infoPtr;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL;
            Guid action = ActionGenericVerifyV2;
            try
            {
                return WinVerifyTrust(IntPtr.Zero, ref action, ref data) == 0;
            }
            finally
            {
                data.dwStateAction = WTD_STATEACTION_CLOSE;
                try { WinVerifyTrust(IntPtr.Zero, ref action, ref data); } catch { }
                Marshal.DestroyStructure(infoPtr, info.GetType());
                Marshal.FreeHGlobal(infoPtr);
            }
        }

        // ---- katalog imzasi ----

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct CATALOG_INFO
        {
            public uint cbStruct;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string wszCatalogFile;
        }

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminAcquireContext2(out IntPtr phCatAdmin, IntPtr pgSubsystem,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszHashAlgorithm, IntPtr pStrongHashPolicy, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile,
            ref uint pcbHash, byte[] pbHash, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash,
            uint dwFlags, ref IntPtr phPrevCatInfo);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

        [DllImport("wintrust.dll", SetLastError = true)]
        static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

        // Dosyanin hash'ini iceren, gecerli dogrulanan katalogun yolu; yoksa null.
        static string FindCatalog(string path)
        {
            foreach (string alg in new string[] { "SHA256", "SHA1" })
            {
                IntPtr admin;
                if (!CryptCATAdminAcquireContext2(out admin, IntPtr.Zero, alg, IntPtr.Zero, 0)) continue;
                try
                {
                    using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                        FileShare.ReadWrite | FileShare.Delete))
                    {
                        uint len = 0;
                        CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref len, null, 0);
                        if (len == 0) continue;
                        var hash = new byte[len];
                        if (!CryptCATAdminCalcHashFromFileHandle2(admin, fs.SafeFileHandle.DangerousGetHandle(), ref len, hash, 0))
                            continue;
                        string tag = BitConverter.ToString(hash).Replace("-", "");

                        IntPtr prev = IntPtr.Zero;
                        IntPtr cat;
                        while ((cat = CryptCATAdminEnumCatalogFromHash(admin, hash, len, 0, ref prev)) != IntPtr.Zero)
                        {
                            var info = new CATALOG_INFO();
                            info.cbStruct = (uint)Marshal.SizeOf(typeof(CATALOG_INFO));
                            if (CryptCATCatalogInfoFromContext(cat, ref info, 0)
                                && VerifyCatalog(info.wszCatalogFile, tag, path, hash, admin))
                            {
                                CryptCATAdminReleaseCatalogContext(admin, cat, 0);
                                return info.wszCatalogFile;
                            }
                            prev = cat; // Enum sonraki cagrida bunu serbest birakir
                        }
                    }
                }
                finally { CryptCATAdminReleaseContext(admin, 0); }
            }
            return null;
        }
    }
}
