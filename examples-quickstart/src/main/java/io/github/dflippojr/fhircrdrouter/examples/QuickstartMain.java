package io.github.dflippojr.fhircrdrouter.examples;

import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.CdsServiceDescriptor;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.PayerRouter;
import io.github.dflippojr.fhircrdrouter.credential.local.EncryptedLocalCredentialProvider;

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
 * <p>Run with {@code ./mvnw install -DskipTests} then
 * {@code ./mvnw -pl examples-quickstart exec:java} from the repo root.
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
            ConnectionRecord record = router.resolve("DEMO-PAYER", io.github.dflippojr.fhircrdrouter.core.Environment.SANDBOX);
            System.out.println("Resolved connection: " + record);

            EncryptedLocalCredentialProvider credentials =
                    new EncryptedLocalCredentialProvider(workDir.resolve("credentials"));
            CdsHooksClient client = new CdsHooksClient(credentials);

            List<CdsServiceDescriptor> services = client.discoverServices(record);
            System.out.println("Discovered services: " + services);

            CdsHookResponse response = client.callHook(record, "prior-auth-check",
                    new CdsHookRequest("order-sign", "quickstart-instance", Map.of(), Map.of()));
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
