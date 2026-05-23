package burp;

import burp.models.Endpoint;
import burp.utils.RiskScorer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class RiskScorerTest {

    private final RiskScorer scorer = new RiskScorer();

    @Test
    void adminEndpointHighRisk() {
        Endpoint e = new Endpoint("example.com", "GET", "/admin/users", 200);
        assertTrue(scorer.score(e) >= 70);
    }

    @Test
    void staticAssetLowRisk() {
        Endpoint e = new Endpoint("example.com", "GET", "/styles/main.css", 200);
        assertTrue(scorer.score(e) <= 20);
    }

    @Test
    void postMethodIncreasesScore() {
        Endpoint get = new Endpoint("example.com", "GET",  "/api/data", 200);
        Endpoint post = new Endpoint("example.com", "POST", "/api/data", 200);
        assertTrue(scorer.score(post) > scorer.score(get));
    }

    @Test
    void deleteMethodHighestAmongMethods() {
        Endpoint del = new Endpoint("example.com", "DELETE", "/api/item", 200);
        Endpoint get = new Endpoint("example.com", "GET",    "/api/item", 200);
        assertTrue(scorer.score(del) > scorer.score(get));
    }

    @Test
    void scoreIsCappedAt100() {
        Endpoint e = new Endpoint("example.com", "DELETE", "/admin/secret/backup/config", 200);
        assertTrue(scorer.score(e) <= 100);
    }
}
