using System;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Threading;

namespace ParentalShield.Services;

public class SecurityService
{
    private readonly ConfigService _configService;
    private DispatcherTimer? _autoLockTimer;

    public bool IsUnlocked { get; private set; }

    public event Action<bool>? LockStateChanged;

    public SecurityService(ConfigService configService)
    {
        _configService = configService;
        IsUnlocked = !HasPasscode(); // If no passcode initially, start unlocked for setup
    }

    public bool HasPasscode()
    {
        var sec = _configService.Config.Security;
        return !string.IsNullOrEmpty(sec.PasscodeHash) && !string.IsNullOrEmpty(sec.Salt);
    }

    public static (string hash, string salt) HashSecret(string secret, byte[]? existingSalt = null)
    {
        byte[] salt = existingSalt ?? RandomNumberGenerator.GetBytes(16);
        byte[] hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, 100000, HashAlgorithmName.SHA512, 64);
        return (Convert.ToHexString(hash), Convert.ToHexString(salt));
    }

    public static bool VerifySecret(string secret, string storedHash, string saltHex)
    {
        if (string.IsNullOrEmpty(storedHash) || string.IsNullOrEmpty(saltHex)) return false;
        try
        {
            byte[] salt = Convert.FromHexString(saltHex);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, 100000, HashAlgorithmName.SHA512, 64);
            byte[] stored = Convert.FromHexString(storedHash);
            return CryptographicOperations.FixedTimeEquals(hash, stored);
        }
        catch
        {
            return false;
        }
    }

    public void SetPasscode(string passcode, string? question = null, string? answer = null)
    {
        if (string.IsNullOrWhiteSpace(passcode) || passcode.Trim().Length < 4)
        {
            throw new ArgumentException("Passcode must be at least 4 digits.");
        }

        var (hash, salt) = HashSecret(passcode.Trim());
        _configService.Config.Security.PasscodeHash = hash;
        _configService.Config.Security.Salt = salt;

        if (!string.IsNullOrWhiteSpace(question) && !string.IsNullOrWhiteSpace(answer))
        {
            var (ansHash, ansSalt) = HashSecret(answer.Trim().ToLowerInvariant());
            _configService.Config.Security.Question = question.Trim();
            _configService.Config.Security.AnswerHash = ansHash;
            _configService.Config.Security.AnswerSalt = ansSalt;
        }

        _configService.SaveConfig();
        IsUnlocked = true;
        ResetAutoLockTimer();
        LockStateChanged?.Invoke(IsUnlocked);
    }

    public bool Unlock(string passcode)
    {
        if (!HasPasscode())
        {
            IsUnlocked = true;
            LockStateChanged?.Invoke(IsUnlocked);
            return true;
        }

        var sec = _configService.Config.Security;
        bool valid = VerifySecret(passcode.Trim(), sec.PasscodeHash!, sec.Salt!);
        if (valid)
        {
            IsUnlocked = true;
            ResetAutoLockTimer();
            LockStateChanged?.Invoke(IsUnlocked);
            return true;
        }

        return false;
    }

    public bool VerifyRecovery(string answer, string newPasscode)
    {
        var sec = _configService.Config.Security;
        if (string.IsNullOrEmpty(sec.AnswerHash) || string.IsNullOrEmpty(sec.AnswerSalt))
        {
            return false;
        }

        bool valid = VerifySecret(answer.Trim().ToLowerInvariant(), sec.AnswerHash, sec.AnswerSalt);
        if (valid)
        {
            SetPasscode(newPasscode);
            return true;
        }

        return false;
    }

    public string? GetSecurityQuestion() => _configService.Config.Security.Question;

    public void Lock()
    {
        IsUnlocked = false;
        _autoLockTimer?.Stop();
        LockStateChanged?.Invoke(IsUnlocked);
    }

    public void ResetAutoLockTimer()
    {
        _autoLockTimer?.Stop();
        int minutes = _configService.Config.AutoLockMinutes;
        if (minutes > 0)
        {
            _autoLockTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMinutes(minutes)
            };
            _autoLockTimer.Tick += (s, e) =>
            {
                Lock();
            };
            _autoLockTimer.Start();
        }
    }
}
