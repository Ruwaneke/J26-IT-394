package demo;

public class UserController {
    public String findUser(String userId) {
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        return query;
    }
}
