

using System.Security.AccessControl;

namespace FolderAuth
{
    internal class Program
    {
        static readonly string path = @"D:\VisualStudioWorkSpace\Auth\TestFolder\"; // İşlem yapılacak dosya veya klasör yolu
        static readonly string targetUser = @"DESKTOP-JRPJQFF\Kadir"; // Tam yetki verilecek kullanıcı
        static void Main(string[] args)
        {
            try
            {
                // DirectoryInfo nesnesini oluştur
                DirectoryInfo directoryInfo = new DirectoryInfo(path);

                // Klasörün mevcut güvenlik ayarlarını al
                DirectorySecurity security = directoryInfo.GetAccessControl();

                //// Devralmayı devre dışı bırak (Üst izinleri kopyalayarak)
                //security.SetAccessRuleProtection(isProtected: true, preserveInheritance: true);
                // Devralmayı kapat ve mevcut izinleri koruma
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

                // Mevcut erişim kurallarını al
                AuthorizationRuleCollection rules = security.GetAccessRules(
                    includeExplicit: true,      // Açıkça tanımlanmış kuralları dahil et
                    includeInherited: true,    // Devralınmış kuralları dahil et
                    typeof(System.Security.Principal.NTAccount) // Kullanıcı/Grup isimlerini çözmek için
                );

                Console.WriteLine("Mevcut yetkiler:");
                foreach (FileSystemAccessRule rule in rules)
                {
                    Console.WriteLine($"- Kullanıcı/Grup: {rule.IdentityReference}");
                    Console.WriteLine($"  Yetki Türü: {rule.AccessControlType}");
                    Console.WriteLine($"  İzinler: {rule.FileSystemRights}");
                    Console.WriteLine($"  Devralma: {rule.IsInherited}");
                    Console.WriteLine();

                    if (rule.IdentityReference.Value.Equals("CREATOR OWNER", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("CREATOR OWNER yetkisi kaldırılıyor...");
                        security.RemoveAccessRule(rule);
                    }                   

                    // SYSTEM grubunun izinlerini kaldır
                    if (rule.IdentityReference.Value.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine(@"NT AUTHORITY\SYSTEM yetkisi kaldırılıyor...");
                        security.RemoveAccessRule(rule);
                    }

                    // Administrators grubunun izinlerini kaldır
                    if (rule.IdentityReference.Value.Equals(@"BUILTIN\Administrators", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine(@"BUILTIN\Administrators yetkisi kaldırılıyor...");
                        security.RemoveAccessRule(rule);
                    }

                    // Users grubunun izinlerini kaldır
                    if (rule.IdentityReference.Value.Equals(@"BUILTIN\Users", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine(@"BUILTIN\Users yetkisi kaldırılıyor...");
                        security.RemoveAccessRule(rule);
                    }
                }

                // Yeni kullanıcıya tam denetim izni ver
                FileSystemAccessRule accessRule = new FileSystemAccessRule(
                    targetUser,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow                    
                );
                security.AddAccessRule(accessRule);

                // Yeni güvenlik ayarlarını klasöre uygula
                directoryInfo.SetAccessControl(security);

                Console.WriteLine($"Sadece {targetUser} kullanıcısına tam yetki verildi.");
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Hata: Yetki yetersizliği. Programı Yönetici olarak çalıştırmayı deneyin.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata: {ex.Message}");
            }
        }
    }
}
