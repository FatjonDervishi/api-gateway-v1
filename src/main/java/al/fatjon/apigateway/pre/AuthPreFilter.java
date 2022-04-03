package al.fatjon.apigateway.pre;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.context.annotation.FilterType;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

import static org.springframework.cloud.netflix.zuul.filters.support.FilterConstants.PRE_TYPE;


public class AuthPreFilter extends ZuulFilter {

    RestTemplate restTemplate = new RestTemplate();
    public static final String UNAUTHORIZED_MESSAGE = "Full authentication is required";

    @Override
    public String filterType() {
        return PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return 0;
    }

    @Override
    public boolean shouldFilter() {
        return !RequestContext.getCurrentContext().contains("/auth");
    }

    @Override
    public Object run() throws ZuulException {
        RequestContext context = RequestContext.getCurrentContext();
        HttpServletRequest request = context.getRequest();
        String authorization = request.getHeader("Authorization");

        if(authorization == null) {
            terminateRequest(context, UNAUTHORIZED_MESSAGE);
        }
        if(!validateToken(authorization).getStatusCode().equals(HttpStatus.OK)) {
            terminateRequest(context, UNAUTHORIZED_MESSAGE);
        }
        return null;
    }

    private ResponseEntity<String> validateToken(String token) {
        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.add("Authorization", token);
        HttpEntity<String> validateTokenRequest = new HttpEntity(null, requestHeaders);
        return restTemplate.exchange("http://localhost:9001/api/auth/user", HttpMethod.GET, validateTokenRequest, String.class);
    }

    private void terminateRequest(RequestContext context ,String message) {
        context.unset();
        context.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
        context.setResponseBody(message);
    }
}
