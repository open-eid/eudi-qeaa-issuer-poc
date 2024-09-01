package ee.ria.eudi.qeaa.issuer.configuration;

import com.nimbusds.oauth2.sdk.dpop.verifiers.DefaultDPoPSingleUseChecker;
import ee.ria.eudi.qeaa.issuer.configuration.properties.IssuerProperties;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.i18n.AcceptHeaderLocaleResolver;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

@Configuration
@EnableCaching
@EnableScheduling
@EnableRetry
@ConfigurationPropertiesScan
public class IssuerConfiguration {

    @Bean
    public X509Certificate issuerCert(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        return (X509Certificate) keyStore.getCertificate(bundle.getKey().getAlias());
    }

    @Bean
    public KeyPair issuerKey(SslBundles sslBundles, X509Certificate issuerCert) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        Key key = keyStore.getKey(bundle.getKey().getAlias(), null);
        return new KeyPair(issuerCert.getPublicKey(), (PrivateKey) key);
    }

    @Bean
    public List<X509Certificate> issuerCertificateChain(SslBundles sslBundles) throws KeyStoreException {
        SslBundle bundle = sslBundles.getBundle("eudi-issuer");
        KeyStore keyStore = bundle.getStores().getKeyStore();
        Certificate[] certificateChain = keyStore.getCertificateChain(bundle.getKey().getAlias());
        return Arrays.stream(certificateChain).map(c -> (X509Certificate) c).toList();
    }

    @Bean
    public DefaultDPoPSingleUseChecker dPoPSingleUseChecker(IssuerProperties.Issuer issuer) {
        long ttl = issuer.dPoPExpiryTime().toSeconds() + issuer.maxClockSkew().toSeconds();
        return new DefaultDPoPSingleUseChecker(ttl, ttl); // TODO: Implement db backed version. Must not be used in load balanced environment.
    }

    @Bean
    public MessageSource messageSource(IssuerProperties issuerProperties) {
        List<Locale> supportedLocales = issuerProperties.issuer().metadata().supportedLocales();
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setDefaultLocale(supportedLocales.getFirst());
        messageSource.setFallbackToSystemLocale(true);
        return messageSource;
    }

    @Bean
    public LocaleResolver localeResolver(IssuerProperties issuerProperties) {
        List<Locale> supportedLocales = issuerProperties.issuer().metadata().supportedLocales();
        AcceptHeaderLocaleResolver localeResolver = new AcceptHeaderLocaleResolver();
        localeResolver.setSupportedLocales(supportedLocales);
        localeResolver.setDefaultLocale(supportedLocales.getFirst());
        return localeResolver;
    }
}
