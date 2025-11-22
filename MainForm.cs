using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace PwdCheckerWinForms
{
    public class MainForm : Form
    {
        private TextBox pwdBox;
        private ProgressBar strengthBar;
        private Label verdictLabel;
        private Button checkBtn;
        private TextBox detailsBox;
        private string breachFile = "breach_hashes.txt";
        private string[] breachLines;

        public MainForm()
        {
            Text = "Password Strength & Breach Checker";
            Width = 600; Height = 350;
            InitializeComponents();
            if(File.Exists(breachFile)) breachLines = File.ReadAllLines(breachFile);
            else breachLines = new string[0];
        }

        private void InitializeComponents()
        {
            pwdBox = new TextBox { Left = 20, Top = 20, Width = 420, PasswordChar='*' };
            checkBtn = new Button { Left = 460, Top = 18, Text = "Check", Width=80 };
            checkBtn.Click += CheckBtn_Click;
            strengthBar = new ProgressBar { Left = 20, Top = 60, Width = 520, Height=20 };
            verdictLabel = new Label { Left=20, Top=90, Width=520 };
            detailsBox = new TextBox { Left=20, Top=120, Width=520, Height=160, Multiline=true, ReadOnly=true, ScrollBars=ScrollBars.Vertical };

            Controls.Add(pwdBox); Controls.Add(checkBtn); Controls.Add(strengthBar); Controls.Add(verdictLabel); Controls.Add(detailsBox);
        }

        private void CheckBtn_Click(object sender, EventArgs e)
        {
            var pwd = pwdBox.Text;
            if(string.IsNullOrEmpty(pwd)) { MessageBox.Show("Enter a password"); return; }
            var score = CalculateEntropyScore(pwd, out string details);
            strengthBar.Value = Math.Min(100, (int)(score * 25)); // map to 0-100 roughly
            verdictLabel.Text = $"Score: {score:F2} (higher is better)";

            var breachMessage = CheckBreach(pwd) ? "Password appears in breach list!" : "No breach found (in local list).";
            detailsBox.Text = details + Environment.NewLine + "Breach check: " + breachMessage;
            if (breachMessage.Contains("appears")) verdictLabel.Text += "  — BREACHED!";
        }

        private double CalculateEntropyScore(string pwd, out string details)
        {
            int len = pwd.Length;
            bool hasLower = pwd.Any(char.IsLower);
            bool hasUpper = pwd.Any(char.IsUpper);
            bool hasDigit = pwd.Any(char.IsDigit);
            bool hasSymbol = pwd.Any(ch => !char.IsLetterOrDigit(ch));

            double pool = 0;
            if (hasLower) pool += 26;
            if (hasUpper) pool += 26;
            if (hasDigit) pool += 10;
            if (hasSymbol) pool += 32;

            double entropy = len * (pool > 0 ? Math.Log(pool, 2) : 0);
            // penalize common patterns
            double penalty = 0;
            if (len < 8) penalty += 2;
            if (pwd.ToLower().Contains("password") || pwd.ToLower().Contains("1234")) penalty += 3;
            if (IsKeyboardPattern(pwd)) penalty += 2;

            double score = Math.Max(0, entropy/10 - penalty); // mapped to 0-10
            details = $"Length: {len}\r\nCharacter classes: { (hasLower? "l":"")}{(hasUpper?"U":"")}{(hasDigit?"D":"")}{(hasSymbol?"S":"")}\r\nEstimated entropy bits: {entropy:F2}\r\nPenalty: {penalty}\r\nScore normalized (0-10): {score:F2}";
            return score;
        }

        private bool IsKeyboardPattern(string s)
        {
            string[] common = {"qwerty","asdf","12345","password","admin"};
            var L = s.ToLower();
            return common.Any(c => L.Contains(c));
        }

        private bool CheckBreach(string pwd)
        {
            // Simulated breach check: SHA1 prefix match against local file of few hashes
            using (var sha1 = SHA1.Create())
            {
                var b = Encoding.UTF8.GetBytes(pwd);
                var hash = sha1.ComputeHash(b);
                var hex = BitConverter.ToString(hash).Replace("-","").ToUpperInvariant();
                // compare prefix 5 chars
                var prefix = hex.Substring(0, 5);
                return breachLines.Contains(prefix);
            }
        }
    }
}
