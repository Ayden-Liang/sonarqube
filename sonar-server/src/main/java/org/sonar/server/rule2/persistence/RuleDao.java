/*
 * SonarQube, open source software quality management tool.
 * Copyright (C) 2008-2014 SonarSource
 * mailto:contact AT sonarsource DOT com
 *
 * SonarQube is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * SonarQube is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.server.rule2.persistence;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import org.apache.ibatis.session.ResultContext;
import org.apache.ibatis.session.ResultHandler;
import org.sonar.api.rule.RuleKey;
import org.sonar.api.utils.System2;
import org.sonar.core.persistence.DbSession;
import org.sonar.core.rule.RuleDto;
import org.sonar.core.rule.RuleMapper;
import org.sonar.core.rule.RuleParamDto;
import org.sonar.server.db.BaseDao;
import org.sonar.server.search.IndexDefinition;
import org.sonar.server.search.action.IndexAction;
import org.sonar.server.search.action.KeyIndexAction;

import javax.annotation.CheckForNull;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RuleDao extends BaseDao<RuleMapper, RuleDto, RuleKey> {

  public RuleDao() {
    this(System2.INSTANCE);
  }

  @VisibleForTesting
  public RuleDao(System2 system) {
    super(IndexDefinition.RULE, RuleMapper.class, system);
  }

  @CheckForNull
  @Override
  public RuleDto doGetByKey(RuleKey key, DbSession session) {
    return mapper(session).selectByKey(key);
  }

  public RuleDto getByName(String name, DbSession session) {
    return mapper(session).selectByName(name);
  }

  @Override
  protected RuleDto doInsert(RuleDto item, DbSession session) {
    mapper(session).insert(item);
    return item;
  }

  @Override
  protected RuleDto doUpdate(RuleDto item, DbSession session) {
    mapper(session).update(item);
    return item;
  }

  @Override
  protected void doDeleteByKey(RuleKey key, DbSession session) {
    throw new UnsupportedOperationException("Rules cannot be deleted");
  }

  @CheckForNull
  @Deprecated
  public RuleDto getById(int id, DbSession session) {
    return mapper(session).selectById(id);
  }

  @CheckForNull
  public RuleDto getParent(RuleDto rule, DbSession session) {
    Preconditions.checkNotNull(rule.getParentId(), "Rule has no persisted parent!");
    return mapper(session).selectById(rule.getParentId());
  }


  @Override
  public void synchronizeAfter(long timestamp, final DbSession session) {
    session.select("selectKeysOfRulesUpdatedSince", new Timestamp(timestamp), new ResultHandler() {
      @Override
      public void handleResult(ResultContext context) {
        Map<String, String> map = (Map) context.getResultObject();
        session.enqueue(new KeyIndexAction<RuleKey>(getIndexType(), IndexAction.Method.UPSERT,
          RuleKey.of(map.get("repoField"), map.get("ruleField"))));
      }
    });
  }

  /**
   * Finder methods for Rules
   */

  public List<RuleDto> findByNonManual(DbSession session) {
    return mapper(session).selectNonManual();
  }

  public List<RuleDto> findAll(DbSession session) {
    return mapper(session).selectAll();
  }

  public List<RuleDto> findByEnabledAndNotManual(DbSession session) {
    return mapper(session).selectEnablesAndNonManual();
  }

  /**
   * Nested DTO RuleParams
   */

  public void addRuleParam(RuleDto rule, RuleParamDto ruleParam, DbSession session) {
    Preconditions.checkNotNull(rule.getId(), "Rule id must be set");
    ruleParam.setRuleId(rule.getId());
    mapper(session).insertParameter(ruleParam);
    this.enqueueInsert(ruleParam, rule.getKey(), session);
  }

  public RuleParamDto updateRuleParam(RuleDto rule, RuleParamDto ruleParam, DbSession session) {
    Preconditions.checkNotNull(rule.getId(), "Rule id must be set");
    Preconditions.checkNotNull(ruleParam.getId(), "Param is not yet persisted must be set");
    ruleParam.setRuleId(rule.getId());
    mapper(session).updateParameter(ruleParam);
    this.enqueueUpdate(ruleParam, rule.getKey(), session);
    return ruleParam;
  }

  public void removeRuleParam(RuleDto rule, RuleParamDto ruleParam, DbSession session) {
    Preconditions.checkNotNull(ruleParam.getId(), "Param is not persisted");
    mapper(session).deleteParameter(ruleParam.getId());
    this.enqueueDelete(ruleParam, rule.getKey(), session);
  }

  /**
   * Finder methods for RuleParams
   */

  public List<RuleParamDto> findAllRuleParams(DbSession session) {
    return mapper(session).selectAllParams();
  }

  public List<RuleParamDto> findRuleParamsByRuleKey(RuleKey key, DbSession session) {
    return mapper(session).selectParamsByRuleKey(key);
  }

  public List<RuleParamDto> findRuleParamsByRules(List<RuleDto> ruleDtos, DbSession session) {
    List<RuleParamDto> ruleParamDtos = new ArrayList<RuleParamDto>();
    for (RuleDto rule : ruleDtos) {
      ruleParamDtos.addAll(findRuleParamsByRuleKey(rule.getKey(), session));
    }
    return ruleParamDtos;
  }

  public RuleParamDto getRuleParamByRuleAndParamKey(RuleDto rule, String key, DbSession session) {
    Preconditions.checkNotNull(rule.getId(), "Rule is not persisted");
    return mapper(session).selectParamByRuleAndKey(rule.getId(), key);
  }

  public List<RuleDto> findRulesByDebtSubCharacteristicId(int id, DbSession session) {
    return mapper(session).selectBySubCharacteristicId(id);
  }

  public List<RuleDto> selectEnabledAndNonManual(DbSession session) {
    return mapper(session).selectEnablesAndNonManual();
  }
}