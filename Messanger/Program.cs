using Npgsql;
using System.Security.Cryptography;
using System.Text;

class Program
{
    public static string user1;
    public static string user2;
    public static List<string?> users = new List<string?>();
    static void Main(string[] args)
    {
        string connectionString = "Server=127.0.0.1;Port=5432;Database=Messanger;User Id=postgres;Password=root";
        while (true)
        {

            while (true)
            {
                Console.Clear();
                Console.Write("1.Sign Up\n2.Log In\n\nChoose:");
                int x = Convert.ToInt16(Console.ReadLine()!);
                if (x == 1)
                {
                    SignUp(connectionString);
                }
                else if (x == 2)
                {
                    break;
                }
            }
            bool check = Login(connectionString);
            if (check == true)
            {
                while (true)
                {
                    Console.Clear();
                    userList(connectionString);
                    Console.Write(":");
                    string UserForSendingMessage = Console.ReadLine()!;
                    if (UserForSendingMessage == "back")
                    {
                        break;
                    }
                    if (users.Any(us => us == UserForSendingMessage))
                    {
                        user2 = UserForSendingMessage;
                        Console.Clear();
                        GetOldMessages(connectionString);
                        createChat(connectionString);
                    }
                    else
                    {
                        Console.WriteLine("not found");
                    }
                }
            }
            else
            {
                Console.WriteLine("not found");

            }
        }
    }

    static void SignUp(string s)
    {
        Console.Write("username:");
        string name = Console.ReadLine()!;
        Console.Write("password:");
        string pass = Console.ReadLine()!;
        using (NpgsqlConnection con = new NpgsqlConnection(s))
        {
            con.Open();
            string query = $"insert into users(username,password,salt) values(@item, @item1, @item3);";
            NpgsqlCommand cmd = new NpgsqlCommand(query, con);
            cmd.Parameters.AddWithValue("item", name);
            cmd.Parameters.AddWithValue("item1", toHash(pass, out byte[] salt));
            cmd.Parameters.AddWithValue("item3", Convert.ToHexString(salt));
            cmd.ExecuteNonQuery();
        }
    }
    static string ToHash(string str)
    {
        foreach (char c in str)
        {
            if (char.IsDigit(c))
            {
                return str;
            }
        }
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(str));

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }

    static void createChat(string s)
    {
        Console.Write("Enter message:");
        string msg = Console.ReadLine()!;
        using (NpgsqlConnection con = new NpgsqlConnection(s))
        {
            con.Open();
            string query = $"insert into users values(@item);";
            NpgsqlCommand cmd = new NpgsqlCommand(query, con);
            cmd.Parameters.AddWithValue("item", msg);
            cmd.ExecuteNonQuery();
        }
    }
    static void GetOldMessages(string s)
    {
        using (NpgsqlConnection con = new NpgsqlConnection(s))
        {
            con.Open();
            string query = $"Select mes from users where (user1 = @u1 and user2 = @u2) or (user1 = @u2 and user2 = @u1);";
            NpgsqlCommand cmd = new NpgsqlCommand(query, con);
            cmd.Parameters.AddWithValue("u1", user1);
            cmd.Parameters.AddWithValue("u2", user2);
            NpgsqlDataReader? reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                if (reader["user1"].ToString() == user2)
                {
                    Console.WriteLine($"{user2} -> {reader["messanges"]}");
                }
                else
                {
                    Console.WriteLine($"You -> {reader["messanges"]}");
                }
            }
        }
    }

    static bool Login(string s)
    {
        Console.Write("username:");
        string name = Console.ReadLine()!;
        Console.Write("password:");
        string pass = Console.ReadLine()!;
        using (NpgsqlConnection con = new NpgsqlConnection(s))
        {
            con.Open();
            string query = $"Select * from users where username = @item1;";
            NpgsqlCommand cmd = new NpgsqlCommand(query, con);
            cmd.Parameters.AddWithValue("item1", name);
            var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                if (HashCheck(pass, reader["password"].ToString()!, reader["salt"].ToString()!))
                {
                    user1 = name;
                    return true;
                }
            }
            return false;
        }
    }
    static void userList(string s)
    {
        using (NpgsqlConnection con = new NpgsqlConnection(s))
        {
            con.Open();
            string query = $"Select username from users where username <> @item;";
            NpgsqlCommand cmd = new NpgsqlCommand(query, con);
            cmd.Parameters.AddWithValue("item", user1);
            var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                Console.WriteLine(reader["username"]);
                users.Add(reader["username"].ToString()!);
            }
        }
    }
    static string toHash(string password, out byte[] salt)
    {

        const int keysiza = 65;
        const int iteratsiya = 350000;
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;

        salt = RandomNumberGenerator.GetBytes(keysiza);

        var hash = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            salt,
            iteratsiya,
            hashAlgorithm,
            keysiza);

        return Convert.ToHexString(hash);
    }
    static bool HashCheck(string password, string hash, string salt)
    {
        byte[] salts = Convert.FromHexString(salt);
        const int keySiza = 65;
        const int iteratsiya = 350000;
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA512;
        var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salts, iteratsiya, hashAlgorithm, keySiza);
        return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
    }

}