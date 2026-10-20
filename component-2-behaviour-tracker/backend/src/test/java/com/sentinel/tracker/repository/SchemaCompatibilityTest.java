package com.sentinel.tracker.repository;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.test.context.ActiveProfiles;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Checks that {@code schema.sql} (the migration record for PostgreSQL, TECHNICAL_OVERVIEW §3.4)
 * matches the JPA entities, and that it can be run again on an existing database (TASKS P1-5).
 *
 * <p>The script runs on its own H2 database in PostgreSQL mode, never on a real database. H2 is
 * close to PostgreSQL for this DDL but not identical, so this catches drift between the
 * entities and the script (§0 rule 7); it does not replace a check on a copy of a real
 * PostgreSQL database.
 */
@DataJpaTest
@ActiveProfiles("test")
class SchemaCompatibilityTest {

    private static final String TABLES =
            "('DEVELOPERS','SECURITY_EVENTS','BEHAVIOUR_LOGS','VULNERABILITY_LIFECYCLE_HISTORY')";

    /** Hibernate's schema, generated from the entities. */
    @Autowired
    private DataSource entityDataSource;

    private SingleConnectionDataSource scriptDataSource;
    private JdbcTemplate script;

    @BeforeEach
    void runSchemaScriptTwice() throws Exception {
        scriptDataSource = new SingleConnectionDataSource(
                "jdbc:h2:mem:schemasql;MODE=PostgreSQL;DATABASE_TO_LOWER=FALSE;DB_CLOSE_DELAY=-1", "sa", "", true);
        script = new JdbcTemplate(scriptDataSource);
        try (Connection connection = scriptDataSource.getConnection()) {
            ScriptUtils.executeSqlScript(connection, new ClassPathResource("schema.sql"));
            // Re-running must succeed: every statement is IF NOT EXISTS (ddl-auto=update databases)
            ScriptUtils.executeSqlScript(connection, new ClassPathResource("schema.sql"));
        }
    }

    @AfterEach
    void dropScriptDatabase() {
        script.execute("DROP ALL OBJECTS");
        scriptDataSource.destroy();
    }

    @Test
    void everyEntityColumn_shouldExistInSchemaSqlWithTheSameNullabilityAndLength() {
        Map<String, Column> entity = columns(new JdbcTemplate(entityDataSource));
        Map<String, Column> sql = columns(script);

        List<String> problems = new ArrayList<>();
        entity.forEach((key, column) -> {
            Column other = sql.get(key);
            if (other == null) {
                problems.add(key + " is mapped by an entity but missing from schema.sql");
                return;
            }
            if (column.nullable() != other.nullable()) {
                problems.add(key + " nullable: entity " + column.nullable() + ", schema.sql " + other.nullable());
            }
            if (!column.family().equals(other.family())) {
                problems.add(key + " type: entity " + column.type() + ", schema.sql " + other.type());
            }
            if (column.family().equals("TEXT") && column.comparableLength() != null && other.comparableLength() != null
                    && !column.comparableLength().equals(other.comparableLength())) {
                problems.add(key + " length: entity " + column.comparableLength() + ", schema.sql " + other.comparableLength());
            }
        });
        sql.keySet().stream().filter(key -> !entity.containsKey(key))
                .forEach(key -> problems.add(key + " is in schema.sql but no entity maps it"));

        assertThat(problems).isEmpty();
    }

    @Test
    void everyEntityIndex_shouldExistInSchemaSql() {
        Set<String> entityIndexes = indexNames(new JdbcTemplate(entityDataSource));
        Set<String> sqlIndexes = indexNames(script);

        assertThat(entityIndexes).isNotEmpty();
        assertThat(sqlIndexes).containsAll(entityIndexes);
    }

    @Test
    void foreignKeys_shouldCascadeOrSetNullAsDocumented() {
        script.update("INSERT INTO developers (developer_identifier) VALUES ('schema-dev')");
        long developerId = script.queryForObject("SELECT id FROM developers", Long.class);
        script.update("INSERT INTO security_events (developer_id, vulnerability_type, severity, file_name, line_number, "
                + "message, detected_at) VALUES (?, 'XSS', 'LOW', 'a.js', 1, 'm', CURRENT_TIMESTAMP)", developerId);
        long eventId = script.queryForObject("SELECT id FROM security_events", Long.class);
        script.update("INSERT INTO behaviour_logs (developer_id, security_event_id, action_type, timestamp) "
                + "VALUES (?, ?, 'OPEN', CURRENT_TIMESTAMP)", developerId, eventId);
        script.update("INSERT INTO vulnerability_lifecycle_history (security_event_id, new_status, changed_at, "
                + "changed_by) VALUES (?, 'DETECTED', CURRENT_TIMESTAMP, 'SYSTEM')", eventId);

        // New rows get the documented defaults; hash columns stay NULL unless the app sets them
        assertThat(script.queryForObject("SELECT current_status FROM security_events", String.class))
                .isEqualTo("DETECTED");
        assertThat(script.queryForObject("SELECT entry_hash FROM vulnerability_lifecycle_history", String.class))
                .isNull();

        // Deleting an event keeps its logs (security_event_id set to NULL) and deletes its history
        script.update("DELETE FROM security_events WHERE id = ?", eventId);
        assertThat(script.queryForObject("SELECT COUNT(*) FROM behaviour_logs WHERE security_event_id IS NULL", Long.class))
                .isEqualTo(1);
        assertThat(script.queryForObject("SELECT COUNT(*) FROM vulnerability_lifecycle_history", Long.class)).isZero();

        // Deleting a developer deletes their logs (TASKS P4-4: retention and deletion)
        script.update("DELETE FROM developers WHERE id = ?", developerId);
        assertThat(script.queryForObject("SELECT COUNT(*) FROM behaviour_logs", Long.class)).isZero();
    }

    @Test
    void uniqueConstraints_shouldRejectDuplicateIdentifiersAndGitHubIds() {
        script.update("INSERT INTO developers (developer_identifier, github_id) VALUES ('one', '1')");

        assertThat(insertFails("INSERT INTO developers (developer_identifier) VALUES ('one')")).isTrue();
        assertThat(insertFails("INSERT INTO developers (developer_identifier, github_id) VALUES ('two', '1')")).isTrue();
        // Several legacy developers without a GitHub id are allowed
        script.update("INSERT INTO developers (developer_identifier) VALUES ('three')");
        script.update("INSERT INTO developers (developer_identifier) VALUES ('four')");
    }

    @Test
    void rerun_shouldMarkLegacyFixLogsClaimedAndLeaveEverythingElse() throws Exception {
        script.update("INSERT INTO developers (developer_identifier) VALUES ('schema-dev')");
        long developerId = script.queryForObject("SELECT id FROM developers", Long.class);
        // Rows as a database written before TASKS P1-6 holds them: no fix_verification
        script.update("INSERT INTO behaviour_logs (developer_id, action_type, timestamp) VALUES (?, 'FIX', CURRENT_TIMESTAMP)",
                developerId);
        script.update("INSERT INTO behaviour_logs (developer_id, action_type, timestamp) VALUES (?, 'OPEN', CURRENT_TIMESTAMP)",
                developerId);
        script.update("INSERT INTO behaviour_logs (developer_id, action_type, timestamp, fix_verification) "
                + "VALUES (?, 'FIX', CURRENT_TIMESTAMP, 'VERIFIED')", developerId);

        try (Connection connection = scriptDataSource.getConnection()) {
            ScriptUtils.executeSqlScript(connection, new ClassPathResource("schema.sql"));
        }

        assertThat(script.queryForList("SELECT action_type || ':' || COALESCE(fix_verification, '-') FROM behaviour_logs "
                + "ORDER BY id", String.class))
                .containsExactly("FIX:CLAIMED", "OPEN:-", "FIX:VERIFIED");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private record Column(String type, boolean nullable, Long declaredLength) {
        /** Type family; H2 creates enum columns as ENUM, schema.sql as VARCHAR. */
        String family() {
            return switch (type) {
                case "CHARACTER VARYING", "ENUM" -> "TEXT";
                case "CHARACTER LARGE OBJECT" -> "CLOB";
                case "TIMESTAMP", "TIMESTAMP WITH TIME ZONE" -> "TIMESTAMP";
                default -> type;
            };
        }

        Long comparableLength() {
            // An ENUM has no declared length to compare
            return type.equals("ENUM") ? null : declaredLength;
        }
    }

    private static Map<String, Column> columns(JdbcTemplate jdbc) {
        Map<String, Column> columns = new TreeMap<>();
        jdbc.query("SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE, CHARACTER_MAXIMUM_LENGTH "
                + "FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'PUBLIC' AND UPPER(TABLE_NAME) IN " + TABLES,
                rs -> {
                    long length = rs.getLong("CHARACTER_MAXIMUM_LENGTH");
                    Long declaredLength = rs.wasNull() ? null : length;
                    columns.put((rs.getString("TABLE_NAME") + "." + rs.getString("COLUMN_NAME")).toLowerCase(),
                            new Column(rs.getString("DATA_TYPE"), "YES".equals(rs.getString("IS_NULLABLE")),
                                    declaredLength));
                });
        return columns;
    }

    private static Set<String> indexNames(JdbcTemplate jdbc) {
        return new TreeSet<>(jdbc.queryForList("SELECT LOWER(INDEX_NAME) FROM INFORMATION_SCHEMA.INDEXES "
                + "WHERE TABLE_SCHEMA = 'PUBLIC' AND UPPER(TABLE_NAME) IN " + TABLES + " AND LOWER(INDEX_NAME) LIKE 'idx_%'",
                String.class));
    }

    private boolean insertFails(String sql) {
        try {
            script.update(sql);
            return false;
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            return true;
        }
    }
}
