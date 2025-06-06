package org.cbioportal.legacy.persistence.mybatis;

import java.util.List;
import org.cbioportal.legacy.model.VariantCount;
import org.cbioportal.legacy.persistence.VariantCountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

@Repository
public class VariantCountMyBatisRepository implements VariantCountRepository {

  @Autowired private VariantCountMapper variantCountMapper;

  @Override
  public List<VariantCount> fetchVariantCounts(
      String molecularProfileId, List<Integer> entrezGeneIds, List<String> keywords) {

    return variantCountMapper.fetchVariantCounts(molecularProfileId, entrezGeneIds, keywords);
  }
}
