package org.cbioportal.legacy.persistence;

import java.util.List;
import java.util.Set;
import org.cbioportal.legacy.model.MolecularProfile;
import org.cbioportal.legacy.model.meta.BaseMeta;
import org.springframework.cache.annotation.Cacheable;

public interface MolecularProfileRepository {

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getAllMolecularProfiles(
      String projection, Integer pageSize, Integer pageNumber, String sortBy, String direction);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  BaseMeta getMetaMolecularProfiles();

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  MolecularProfile getMolecularProfile(String molecularProfileId);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getMolecularProfiles(Set<String> molecularProfileIds, String projection);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  BaseMeta getMetaMolecularProfiles(Set<String> molecularProfileIds);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getAllMolecularProfilesInStudy(
      String studyId,
      String projection,
      Integer pageSize,
      Integer pageNumber,
      String sortBy,
      String direction);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  BaseMeta getMetaMolecularProfilesInStudy(String studyId);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getMolecularProfilesInStudies(List<String> studyIds, String projection);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  BaseMeta getMetaMolecularProfilesInStudies(List<String> studyIds);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getMolecularProfilesReferredBy(String referringMolecularProfileId);

  @Cacheable(
      cacheResolver = "generalRepositoryCacheResolver",
      condition = "@cacheEnabledConfig.getEnabled()")
  List<MolecularProfile> getMolecularProfilesReferringTo(String referredMolecularProfileId);
}
