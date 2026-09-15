package io.github.dflippo.fhircrdrouter.examples;

import io.github.dflippo.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippo.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippo.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippo.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippo.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippo.fhircrdrouter.core.ConnectionStore;
import io.github.dflippo.fhircrdrouter.core.FileBasedConnectionStore;
import io.github.dflippo.fhircrdrouter.core.PayerRouter;
import io.github.dflippo.fhircrdrouter.credential.local.EncryptedLocalCredentialProvider;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * End-to-end demo: start the mock payer server, load a sample connection
 * record, resolve it through {@link PayerRouter}, and make a real CDS Hooks
 * discovery + hook call against the mock server via {@link CdsHooksClient}.
 *
 * <p>Run with {@code mvn -pl examples-quickstart exec:java} from the repo
 * root (after installing a JDK 17+ and Maven — see the root DECISIONS.md).
 */
public final class QuickstartMain {

    public static void main(String[] args) throws IOException {
        MockCdsHooksServer mockServer = new MockCdsHooksServer(8089);
        mockServer.start();
        System.out.println("Mock payer server listening on http://localhost:" + mockServer.port());

        try {
            Path workDir = Files.createTempDirectory("fhir-crd-router-quickstart");
            ConnectionStore store = new FileBasedConnectionStore(workDir.resolve("connections.yaml"));
            seedFromSampleYaml(store);

            PayerRouter router = new PayerRouter(store);
            ConnectionRecord record = router.resolve("DEMO-PAYER", io.github.dflippo.fhircrdrouter.core.Environment.SANDBOX);
            System.out.println("Resolved connection: " + record);

            EncryptedLocalCredentialProvider credentials =
                    new EncryptedLocalCredentialProvider(workDir.resolve("credentials"));
            CdsHooksClient client = new CdsHooksClient(credentials);

            List<CdsServiceDescriptor> services = client.discoverServices(record);
            System.out.println("Discovered services: " + services);

            CdsHookResponse response = client.callHook(record, "prior-auth-check",
                    new CdsHookRequest("patient-view", "quickstart-instance", Map.of(), Map.of()));
            System.out.println("Hook response cards: " + response.cards());
        } finally {
            mockServer.stop();
        }
    }

    /**
     * Reads {@code sample-connections.yaml} from the classpath and writes each
     * record into the given store via the normal {@link ConnectionRecord}
     * builder — done by hand here (rather than bulk-loading the YAML straight
     * into the store) just to keep this example's only Jackson-YAML-specific
     * code inside {@code FileBasedConnectionStore} itself.
     */
    private static void seedFromSampleYaml(ConnectionStore store) {
        try (InputStream in = QuickstartMain.class.getResourceAsStream("/sample-connections.yaml")) {
            if (in == null) {
                throw new IllegalStateException("sample-connections.yaml not found on classpath");
            }
            com.fasterxml.jackson.databind.ObjectMapper yamlMapper =
                    new com.fasterxml.jackson.databind.ObjectMapper(new com.fasterxml.jackson.dataformat.yaml.YAMLFactory());
            ConnectionRecord[] records = yamlMapper.readValue(in, ConnectionRecord[].class);
            for (ConnectionRecord record : records) {
                store.save(record);
            }
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
