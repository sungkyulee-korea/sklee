import java.sql.*;

public class BadExample {
    public void searchUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE username = '" + username + "'"; // <-- 취약: 직접 concat
        ResultSet rs = stmt.executeQuery(sql);
        // ...
    }
}