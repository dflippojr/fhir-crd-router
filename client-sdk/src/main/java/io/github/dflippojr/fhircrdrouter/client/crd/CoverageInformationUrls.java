package io.github.dflippojr.fhircrdrouter.client.crd;

/**
 * Sub-extension urls of CRD {@code ext-coverage-information}
 * (<a href="https://hl7.org/fhir/us/davinci-crd/STU2.2/StructureDefinition-ext-coverage-information.html">CRD 2.2.1</a>),
 * named once so {@link CoverageInformation} and {@link CoverageInformationValidator} can't disagree.
 */
final class CoverageInformationUrls {

    /** The FHIR element holding an extension's sub-extensions. */
    static final String EXTENSION = "extension";

    static final String COVERAGE = "coverage";
    static final String COVERED = "covered";
    static final String PA_NEEDED = "pa-needed";
    static final String DOC_NEEDED = "doc-needed";
    static final String DOC_PURPOSE = "doc-purpose";
    static final String INFO_NEEDED = "info-needed";
    static final String REASON = "reason";
    static final String DATE = "date";
    static final String EXPIRY_DATE = "expiry-date";
    static final String COVERAGE_ASSERTION_ID = "coverage-assertion-id";
    static final String SATISFIED_PA_ID = "satisfied-pa-id";
    static final String QUESTIONNAIRE = "questionnaire";
    static final String DETAIL = "detail";
    /** Pre-2.x name for {@link #COVERAGE_ASSERTION_ID}, still sent by the HL7 CRD reference implementation. */
    static final String LEGACY_IDENTIFIER = "identifier";
    /** Reference-implementation-only sub-extension. */
    static final String RI_COVERAGE_INFO = "coverageInfo";

    private CoverageInformationUrls() { }
}
