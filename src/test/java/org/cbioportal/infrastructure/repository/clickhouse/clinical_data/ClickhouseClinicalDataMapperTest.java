package org.cbioportal.infrastructure.repository.clickhouse.clinical_data;

import static org.junit.Assert.*;

import java.math.BigDecimal;
import java.util.Collections;
import java.util.List;
import org.cbioportal.domain.studyview.StudyViewFilterFactory;
import org.cbioportal.infrastructure.repository.clickhouse.AbstractTestcontainers;
import org.cbioportal.infrastructure.repository.clickhouse.config.MyBatisConfig;
import org.cbioportal.legacy.model.ClinicalDataCount;
import org.cbioportal.legacy.web.parameter.ClinicalDataFilter;
import org.cbioportal.legacy.web.parameter.DataFilterValue;
import org.cbioportal.legacy.web.parameter.StudyViewFilter;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@Import(MyBatisConfig.class)
@DataJpaTest
@DirtiesContext
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@ContextConfiguration(initializers = AbstractTestcontainers.Initializer.class)
public class ClickhouseClinicalDataMapperTest {
  private static final String STUDY_ACC_TCGA = "acc_tcga";
  private static final String STUDY_GENIE_PUB = "study_genie_pub";

  @Autowired private ClickhouseClinicalDataMapper mapper;

  @Test
  public void getMutationCounts() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"),
            Collections.emptyList(),
            Collections.emptyList());

    var mutationsCountsOptional =
        clinicalDataCountItems.stream()
            .filter(c -> c.getAttributeId().equals("mutation_count"))
            .findFirst();

    assertTrue(mutationsCountsOptional.isPresent());
    var mutationsCounts = mutationsCountsOptional.get().getCounts();

    assertEquals(6, mutationsCounts.size());
    assertEquals(1, findClinicaDataCount(mutationsCounts, "11"));
    assertEquals(1, findClinicaDataCount(mutationsCounts, "6"));
    assertEquals(2, findClinicaDataCount(mutationsCounts, "4"));
    assertEquals(4, findClinicaDataCount(mutationsCounts, "2"));
    assertEquals(2, findClinicaDataCount(mutationsCounts, "1"));
    // 1 empty string + 1 'NAN' + 15 samples with no data
    assertEquals(17, findClinicaDataCount(mutationsCounts, "NA"));
  }

  @Test
  public void getCenterCounts() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    var clinicalDataCounts =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(),
            List.of("center"),
            Collections.emptyList());

    var categoricalClinicalDataCountsOptional =
        clinicalDataCounts.stream().filter(c -> c.getAttributeId().equals("center")).findFirst();

    assertTrue(categoricalClinicalDataCountsOptional.isPresent());
    var categoricalClinicalDataCounts = categoricalClinicalDataCountsOptional.get().getCounts();

    assertEquals(7, categoricalClinicalDataCounts.size());
    assertEquals(3, findClinicaDataCount(categoricalClinicalDataCounts, "msk"));
    assertEquals(2, findClinicaDataCount(categoricalClinicalDataCounts, "dfci"));
    assertEquals(2, findClinicaDataCount(categoricalClinicalDataCounts, "chop"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "mda"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "ohsu"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "ucsf"));
    // 1 empty string + 1 'NA' + 12 samples with no data
    assertEquals(14, findClinicaDataCount(categoricalClinicalDataCounts, "NA"));
  }

  @Test
  public void getDeadCounts() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    var clinicalDataCounts =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(),
            List.of("dead"),
            Collections.emptyList());

    var categoricalClinicalDataCountsOptional =
        clinicalDataCounts.stream().filter(c -> c.getAttributeId().equals("dead")).findFirst();

    assertTrue(categoricalClinicalDataCountsOptional.isPresent());
    var categoricalClinicalDataCounts = categoricalClinicalDataCountsOptional.get().getCounts();

    assertEquals(10, categoricalClinicalDataCounts.size());
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "True"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "TRUE"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "true"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "False"));
    assertEquals(2, findClinicaDataCount(categoricalClinicalDataCounts, "FALSE"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "false"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "Not Released"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "Not Collected"));
    assertEquals(1, findClinicaDataCount(categoricalClinicalDataCounts, "Unknown"));
    // 1 empty string + 1 'N/A' + 12 samples with no data
    assertEquals(14, findClinicaDataCount(categoricalClinicalDataCounts, "NA"));
  }

  @Test
  public void getMutationAndCenterCounts() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    var combinedClinicalDataCounts =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"),
            List.of("center"),
            Collections.emptyList());

    assertEquals(2, combinedClinicalDataCounts.size());
  }

  @Test
  public void getAgeCounts() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(),
            List.of("age"),
            Collections.emptyList());

    var ageCountsOptional =
        clinicalDataCountItems.stream().filter(c -> c.getAttributeId().equals("age")).findFirst();

    assertTrue(ageCountsOptional.isPresent());
    var ageCounts = ageCountsOptional.get().getCounts();

    assertAgeCounts(ageCounts);

    // 1 empty string + 1 'NAN' + 1 'N/A' + 1 patient without data
    assertEquals(4, findClinicaDataCount(ageCounts, "NA"));
  }

  @Test
  public void getAgeCountsForMultipleStudies() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB, STUDY_ACC_TCGA));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(),
            List.of("age"),
            Collections.emptyList());

    var ageCountsOptional =
        clinicalDataCountItems.stream().filter(c -> c.getAttributeId().equals("age")).findFirst();

    assertTrue(ageCountsOptional.isPresent());
    var ageCounts = ageCountsOptional.get().getCounts();

    // everything should be exactly the same as single study (STUDY_GENIE_PUB) filter
    // except NA counts
    assertAgeCounts(ageCounts);

    // 1 empty string + 1 'NAN' + 1 'N/A' + 1 GENIE_PUB patient without data + 4 ACC_TCGA data
    // without data
    assertEquals(8, findClinicaDataCount(ageCounts, "NA"));
  }

  private void assertAgeCounts(List<ClinicalDataCount> ageCounts) {
    assertEquals(15, ageCounts.size());

    assertEquals(3, findClinicaDataCount(ageCounts, "<18"));
    assertEquals(1, findClinicaDataCount(ageCounts, "18"));
    assertEquals(1, findClinicaDataCount(ageCounts, "22"));
    assertEquals(2, findClinicaDataCount(ageCounts, "42"));
    assertEquals(1, findClinicaDataCount(ageCounts, "66"));
    assertEquals(1, findClinicaDataCount(ageCounts, "66"));
    assertEquals(1, findClinicaDataCount(ageCounts, "68"));
    assertEquals(1, findClinicaDataCount(ageCounts, "77"));
    assertEquals(1, findClinicaDataCount(ageCounts, "78"));
    assertEquals(1, findClinicaDataCount(ageCounts, "79"));
    assertEquals(2, findClinicaDataCount(ageCounts, "80"));
    assertEquals(2, findClinicaDataCount(ageCounts, "82"));
    assertEquals(1, findClinicaDataCount(ageCounts, "89"));
    assertEquals(2, findClinicaDataCount(ageCounts, ">89"));
    assertEquals(1, findClinicaDataCount(ageCounts, "UNKNOWN"));
  }

  @Test
  public void getMutationCountsFilteredByAge() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    // filter patients with age between 20 and 70
    // (there are 5 patients within this range, which are 307..311)
    ClinicalDataFilter filter = buildClinicalDataFilter("age", 20, 70);
    studyViewFilter.setClinicalDataFilters(List.of(filter));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"),
            Collections.emptyList(),
            Collections.emptyList());

    var mutationsCountsOptional =
        clinicalDataCountItems.stream()
            .filter(c -> c.getAttributeId().equals("mutation_count"))
            .findFirst();

    assertTrue(mutationsCountsOptional.isPresent());
    var mutationCountsFiltered = mutationsCountsOptional.get().getCounts();

    assertEquals(3, mutationCountsFiltered.size());
    assertEquals(2, findClinicaDataCount(mutationCountsFiltered, "2"));
    assertEquals(2, findClinicaDataCount(mutationCountsFiltered, "1"));
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "NA"));
  }

  @Test
  public void getMutationCountsFilteredByAgeWithOpenStartValues() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    // filter patients with age less than 20
    // (there are 4 patients within this range, which are 301, 302, 303, and 306)
    ClinicalDataFilter filter = buildClinicalDataFilter("age", null, 20);
    studyViewFilter.setClinicalDataFilters(List.of(filter));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"),
            Collections.emptyList(),
            Collections.emptyList());

    var mutationsCountsOptional =
        clinicalDataCountItems.stream()
            .filter(c -> c.getAttributeId().equals("mutation_count"))
            .findFirst();

    assertTrue(mutationsCountsOptional.isPresent());
    var mutationCountsFiltered = mutationsCountsOptional.get().getCounts();

    assertEquals(4, mutationCountsFiltered.size());
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "11")); // patient 301
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "6")); // patient 302
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "4")); // patient 303
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "2")); // patient 306

    // no patients/samples with NA
    assertEquals(0, findClinicaDataCount(mutationCountsFiltered, "NA"));
  }

  @Test
  public void getMutationCountsFilteredByAgeWithOpenEndValues() {
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_GENIE_PUB));

    // filter patients with age greater than 80
    // (there are 4 patients within this range, which are 317, 318, 319, 304, and 305)
    ClinicalDataFilter filter = buildClinicalDataFilter("age", 80, null);
    studyViewFilter.setClinicalDataFilters(List.of(filter));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"),
            Collections.emptyList(),
            Collections.emptyList());

    var mutationsCountsOptional =
        clinicalDataCountItems.stream()
            .filter(c -> c.getAttributeId().equals("mutation_count"))
            .findFirst();

    assertTrue(mutationsCountsOptional.isPresent());
    var mutationCountsFiltered = mutationsCountsOptional.get().getCounts();

    assertEquals(3, mutationCountsFiltered.size());
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "4")); // patient 304
    assertEquals(1, findClinicaDataCount(mutationCountsFiltered, "2")); // patient 305

    // patients/samples with NA data: 317, 318, and 319
    assertEquals(3, findClinicaDataCount(mutationCountsFiltered, "NA"));
  }

  @Test
  public void getConflictingAttributeCounts() {
    // Test conflicting attributes where same attribute name exists in both sample and patient
    // levels
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_ACC_TCGA, STUDY_GENIE_PUB));

    var clinicalDataCountItems =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(), // no sample attributes
            Collections.emptyList(), // no patient attributes
            List.of("subtype") // only conflicting attributes
            );

    var subtypeCountsOptional =
        clinicalDataCountItems.stream()
            .filter(c -> c.getAttributeId().equals("subtype"))
            .findFirst();

    assertTrue("Subtype counts should be present", subtypeCountsOptional.isPresent());
    var subtypeCounts = subtypeCountsOptional.get().getCounts();

    // Expected: sample-level data from acc_tcga + patient-level data from study_genie_pub
    assertEquals("Should have 5 subtype categories", 5, subtypeCounts.size());

    assertEquals("Luminal A count", 2, findClinicaDataCount(subtypeCounts, "Luminal A"));
    assertEquals("Luminal B count", 2, findClinicaDataCount(subtypeCounts, "Luminal B"));
    assertEquals("HER2+ count", 2, findClinicaDataCount(subtypeCounts, "HER2+"));
    assertEquals(
        "Triple Negative count", 1, findClinicaDataCount(subtypeCounts, "Triple Negative"));

    // NA count calculated using total SAMPLE count due to isConflicting=true
    assertTrue("NA count should be > 0", findClinicaDataCount(subtypeCounts, "NA") > 0);
  }

  @Test
  public void getConflictingAttributeCountsWithSampleAndPatientAttributes() {
    // Test conflicting attributes combined with regular sample/patient attributes
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_ACC_TCGA, STUDY_GENIE_PUB));

    var combinedClinicalDataCounts =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            List.of("mutation_count"), // sample attribute
            List.of("center"), // patient attribute
            List.of("subtype") // conflicting attribute
            );

    // Verify all three attribute types are returned via UNION logic
    assertEquals("Should have 3 attributes", 3, combinedClinicalDataCounts.size());

    assertTrue(
        "mutation_count should be present",
        combinedClinicalDataCounts.stream()
            .anyMatch(c -> c.getAttributeId().equals("mutation_count")));
    assertTrue(
        "center should be present",
        combinedClinicalDataCounts.stream().anyMatch(c -> c.getAttributeId().equals("center")));
    assertTrue(
        "subtype should be present",
        combinedClinicalDataCounts.stream().anyMatch(c -> c.getAttributeId().equals("subtype")));
  }

  @Test
  public void getConflictingAttributeCountsWithFiltering() {
    // Test conflicting attributes work correctly with study view filtering
    StudyViewFilter studyViewFilter = new StudyViewFilter();
    studyViewFilter.setStudyIds(List.of(STUDY_ACC_TCGA, STUDY_GENIE_PUB));

    // Filter for patients with age > 75 (patients 304, 305, 312, 313, 314, 315, 316, 317, 318, 319)
    ClinicalDataFilter filter = buildClinicalDataFilter("age", 75, null);
    studyViewFilter.setClinicalDataFilters(List.of(filter));

    var filteredClinicalDataCounts =
        mapper.getClinicalDataCounts(
            StudyViewFilterFactory.make(studyViewFilter, null, studyViewFilter.getStudyIds(), null),
            Collections.emptyList(),
            Collections.emptyList(),
            List.of("subtype"));

    var subtypeCountsOptional =
        filteredClinicalDataCounts.stream()
            .filter(c -> c.getAttributeId().equals("subtype"))
            .findFirst();

    assertTrue("Filtered subtype counts should be present", subtypeCountsOptional.isPresent());
    var subtypeCounts = subtypeCountsOptional.get().getCounts();

    // After filtering: 10 total samples, 4 with actual values, 6 NA
    assertEquals("Should have 5 subtype categories after filtering", 5, subtypeCounts.size());

    assertEquals(
        "Triple Negative count", 1, findClinicaDataCount(subtypeCounts, "Triple Negative"));
    assertEquals("Luminal A count", 1, findClinicaDataCount(subtypeCounts, "Luminal A"));
    assertEquals("HER2+ count", 1, findClinicaDataCount(subtypeCounts, "HER2+"));
    assertEquals("Luminal B count", 1, findClinicaDataCount(subtypeCounts, "Luminal B"));
    assertEquals("NA count", 6, findClinicaDataCount(subtypeCounts, "NA"));

    // Verify NA calculation uses sample count even with filtering (isConflicting=true)
    assertTrue(
        "Should have NA count with filtering", findClinicaDataCount(subtypeCounts, "NA") > 0);
  }

  private ClinicalDataFilter buildClinicalDataFilter(
      String attributeId, Integer start, Integer end) {
    DataFilterValue value = new DataFilterValue();
    if (start != null) {
      value.setStart(BigDecimal.valueOf(start));
    }
    if (end != null) {
      value.setEnd(BigDecimal.valueOf(end));
    }

    ClinicalDataFilter filter = new ClinicalDataFilter();
    filter.setAttributeId(attributeId);
    filter.setValues(List.of(value));

    return filter;
  }

  private int findClinicaDataCount(List<ClinicalDataCount> counts, String attrValue) {
    var count = counts.stream().filter(c -> c.getValue().equals(attrValue)).findAny().orElse(null);

    return count == null ? 0 : count.getCount();
  }
}
