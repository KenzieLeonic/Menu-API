package th.ac.ku.menu.security;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.List;

//Jwt คือ ของ Spring Security ดึงจาก token
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {
    private final String audience;

    public AudienceValidator(String audience) {
        this.audience = audience;
    }

    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> audiences = jwt.getAudience(); //ดึง Audience
        if (audiences.contains(this.audience)) {
            return OAuth2TokenValidatorResult.success(); //เอา security success
        }
        OAuth2Error err = new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN); //Invalid Token (เก็บ error)
        return OAuth2TokenValidatorResult.failure(err);
    }
}

