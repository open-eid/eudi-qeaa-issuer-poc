package ee.ria.eudi.qeaa.issuer;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import lombok.extern.slf4j.Slf4j;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Matcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static ch.qos.logback.classic.Level.ERROR;
import static ch.qos.logback.classic.Level.INFO;
import static ch.qos.logback.classic.Level.WARN;
import static java.util.List.of;
import static java.util.stream.Collectors.toList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInRelativeOrder;
import static org.hamcrest.Matchers.empty;
import static org.slf4j.Logger.ROOT_LOGGER_NAME;
import static org.slf4j.LoggerFactory.getLogger;

@Slf4j
public class BaseTestLoggingAssertion {

    private static ListAppender<ILoggingEvent> mockLogAppender;

    @BeforeEach
    void addMockLogAppender() {
        mockLogAppender = new ListAppender<>();
        ((Logger) getLogger(ROOT_LOGGER_NAME)).addAppender(mockLogAppender);
        mockLogAppender.start();
    }

    @AfterEach
    void assertMissedErrorsAndWarnings() {
        List<ILoggingEvent> unmatchedErrorsAndWarnings = mockLogAppender.list.stream()
            .filter(e -> e.getLevel() == ERROR || e.getLevel() == WARN)
            .collect(Collectors.toList());
        ((Logger) getLogger(ROOT_LOGGER_NAME)).detachAppender(mockLogAppender);
        assertThat(unmatchedErrorsAndWarnings, empty());
    }

    protected List<ILoggingEvent> assertInfoIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(INFO, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertWarningIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(WARN, messagesInRelativeOrder);
    }

    protected List<ILoggingEvent> assertErrorIsLogged(String... messagesInRelativeOrder) {
        return assertMessageIsLogged(ERROR, messagesInRelativeOrder);
    }

    @SuppressWarnings("unchecked")
    private List<ILoggingEvent> assertMessageIsLogged(Level loggingLevel, String... messagesInRelativeOrder) {
        List<String> expectedMessages = of(messagesInRelativeOrder);
        Stream<ILoggingEvent> eventStream = mockLogAppender.list.stream()
            .filter(e -> loggingLevel == null || e.getLevel() == loggingLevel);
        List<ILoggingEvent> events = eventStream.collect(toList());
        mockLogAppender.list.removeAll(events);
        List<String> messages = events.stream().map(ILoggingEvent::getFormattedMessage).collect(toList());
        assertThat("Expected log messages not found in output.\n\tExpected log messages: " + of(messagesInRelativeOrder) + ",\n\tActual log messages: " + messages,
            messages, containsInRelativeOrder(expectedMessages.stream().map(CoreMatchers::startsWith).toArray(Matcher[]::new)));
        return events;
    }
}
