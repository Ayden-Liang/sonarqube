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
package org.sonar.batch.index;

import com.google.common.base.CharMatcher;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.ibatis.session.ResultContext;
import org.apache.ibatis.session.ResultHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.api.batch.fs.InputPath;
import org.sonar.api.batch.fs.internal.DefaultInputFile;
import org.sonar.api.batch.sensor.duplication.DuplicationGroup;
import org.sonar.api.batch.sensor.duplication.DuplicationGroup.Block;
import org.sonar.api.batch.sensor.symbol.Symbol;
import org.sonar.api.measures.CoreMetrics;
import org.sonar.api.measures.Measure;
import org.sonar.api.utils.DateUtils;
import org.sonar.api.utils.KeyValueFormat;
import org.sonar.api.utils.System2;
import org.sonar.batch.ProjectTree;
import org.sonar.batch.duplication.DuplicationCache;
import org.sonar.batch.highlighting.SyntaxHighlightingData;
import org.sonar.batch.highlighting.SyntaxHighlightingRule;
import org.sonar.batch.scan.filesystem.InputPathCache;
import org.sonar.batch.scan.measure.MeasureCache;
import org.sonar.batch.source.CodeColorizers;
import org.sonar.batch.symbol.SymbolData;
import org.sonar.core.persistence.DbSession;
import org.sonar.core.persistence.MyBatis;
import org.sonar.core.source.SnapshotDataTypes;
import org.sonar.core.source.db.FileSourceDto;
import org.sonar.core.source.db.FileSourceMapper;
import org.sonar.server.source.db.FileSourceDb;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class SourcePersister implements ScanPersister {

  private static final Logger LOG = LoggerFactory.getLogger(SourcePersister.class);

  private static final String BOM = "\uFEFF";
  private final InputPathCache inputPathCache;
  private final MyBatis mybatis;
  private final MeasureCache measureCache;
  private final ComponentDataCache componentDataCache;
  private final System2 system2;
  private final ProjectTree projectTree;
  private final ResourceCache resourceCache;
  private CodeColorizers codeColorizers;
  private DuplicationCache duplicationCache;

  public SourcePersister(InputPathCache inputPathCache,
    MyBatis mybatis, MeasureCache measureCache, ComponentDataCache componentDataCache, ProjectTree projectTree, System2 system2,
    ResourceCache resourceCache, CodeColorizers codeColorizers, DuplicationCache duplicationCache) {
    this.inputPathCache = inputPathCache;
    this.mybatis = mybatis;
    this.measureCache = measureCache;
    this.componentDataCache = componentDataCache;
    this.projectTree = projectTree;
    this.system2 = system2;
    this.resourceCache = resourceCache;
    this.codeColorizers = codeColorizers;
    this.duplicationCache = duplicationCache;
  }

  @Override
  public void persist() {
    // Don't use batch insert for file_sources since keeping all data in memory can produce OOM for big files
    try (DbSession session = mybatis.openSession(false)) {

      final Map<String, FileSourceDto> previousDtosByUuid = new HashMap<>();
      session.select("org.sonar.core.source.db.FileSourceMapper.selectHashesForProject", projectTree.getRootProject().getUuid(), new ResultHandler() {
        @Override
        public void handleResult(ResultContext context) {
          FileSourceDto dto = (FileSourceDto) context.getResultObject();
          previousDtosByUuid.put(dto.getFileUuid(), dto);
        }
      });

      FileSourceMapper mapper = session.getMapper(FileSourceMapper.class);

      for (InputPath inputPath : inputPathCache.all()) {
        if (inputPath instanceof InputFile) {
          persist(session, mapper, inputPath, previousDtosByUuid);
        }
      }
    } catch (Exception e) {
      throw new IllegalStateException("Unable to save file sources", e);
    }

  }

  private void persist(DbSession session, FileSourceMapper mapper, InputPath inputPath, Map<String, FileSourceDto> previousDtosByUuid) {
    DefaultInputFile inputFile = (DefaultInputFile) inputPath;
    org.sonar.api.resources.File resource = (org.sonar.api.resources.File) resourceCache.get(inputFile.key()).resource();
    String fileUuid = resource.getUuid();

    byte[] data = computeData(inputFile);
    String dataHash = DigestUtils.md5Hex(data);
    FileSourceDto previousDto = previousDtosByUuid.get(fileUuid);
    if (previousDto == null) {
      FileSourceDto dto = new FileSourceDto()
        .setProjectUuid(projectTree.getRootProject().getUuid())
        .setFileUuid(fileUuid)
        .setBinaryData(data)
        .setDataHash(dataHash)
        .setSrcHash(inputFile.hash())
        .setLineHashes(lineHashesAsMd5Hex(inputFile))
        .setCreatedAt(system2.now())
        .setUpdatedAt(system2.now());
      mapper.insert(dto);
      session.commit();
    } else {
      // Update only if data_hash has changed or if src_hash is missing (progressive migration)
      if (!dataHash.equals(previousDto.getDataHash()) || !inputFile.hash().equals(previousDto.getSrcHash())) {
        previousDto
          .setBinaryData(data)
          .setDataHash(dataHash)
          .setSrcHash(inputFile.hash())
          .setLineHashes(lineHashesAsMd5Hex(inputFile))
          .setUpdatedAt(system2.now());
        mapper.update(previousDto);
        session.commit();
      }
    }
  }

  @CheckForNull
  private String lineHashesAsMd5Hex(DefaultInputFile inputFile) {
    if (inputFile.lines() == 0) {
      return null;
    }
    // A md5 string is 32 char long + '\n' = 33
    StringBuilder result = new StringBuilder(inputFile.lines() * (32 + 1));
    for (byte[] lineHash : inputFile.lineHashes()) {
      if (result.length() > 0) {
        result.append("\n");
      }
      result.append(lineHash != null ? Hex.encodeHexString(lineHash) : "");
    }
    return result.toString();
  }

  private byte[] computeData(DefaultInputFile file) {
    try {
      List<String> lines = FileUtils.readLines(file.file(), file.encoding());
      // Missing empty last line
      if (lines.size() == file.lines() - 1) {
        lines.add("");
      }

      Map<Integer, String> authorsByLine = getLineMetric(file, CoreMetrics.SCM_AUTHORS_BY_LINE_KEY);
      Map<Integer, String> revisionsByLine = getLineMetric(file, CoreMetrics.SCM_REVISIONS_BY_LINE_KEY);
      Map<Integer, String> datesByLine = getLineMetric(file, CoreMetrics.SCM_LAST_COMMIT_DATETIMES_BY_LINE_KEY);
      Map<Integer, String> utHitsByLine = getLineMetric(file, CoreMetrics.COVERAGE_LINE_HITS_DATA_KEY);
      Map<Integer, String> utCondByLine = getLineMetric(file, CoreMetrics.CONDITIONS_BY_LINE_KEY);
      Map<Integer, String> utCoveredCondByLine = getLineMetric(file, CoreMetrics.COVERED_CONDITIONS_BY_LINE_KEY);
      Map<Integer, String> itHitsByLine = getLineMetric(file, CoreMetrics.IT_COVERAGE_LINE_HITS_DATA_KEY);
      Map<Integer, String> itCondByLine = getLineMetric(file, CoreMetrics.IT_CONDITIONS_BY_LINE_KEY);
      Map<Integer, String> itCoveredCondByLine = getLineMetric(file, CoreMetrics.IT_COVERED_CONDITIONS_BY_LINE_KEY);
      Map<Integer, String> overallHitsByLine = getLineMetric(file, CoreMetrics.OVERALL_COVERAGE_LINE_HITS_DATA_KEY);
      Map<Integer, String> overallCondByLine = getLineMetric(file, CoreMetrics.OVERALL_CONDITIONS_BY_LINE_KEY);
      Map<Integer, String> overallCoveredCondByLine = getLineMetric(file, CoreMetrics.OVERALL_COVERED_CONDITIONS_BY_LINE_KEY);
      SyntaxHighlightingData highlighting = loadHighlighting(file);
      String[] highlightingPerLine = computeHighlightingPerLine(file, highlighting);
      String[] symbolReferencesPerLine = computeSymbolReferencesPerLine(file, loadSymbolReferences(file));
      String[] duplicationsPerLine = computeDuplicationsPerLine(file, duplicationCache.byComponent(file.key()));

      FileSourceDb.Data.Builder dataBuilder = FileSourceDb.Data.newBuilder();
      for (int lineIdx = 1; lineIdx <= file.lines(); lineIdx++) {
        FileSourceDb.Line.Builder lineBuilder = dataBuilder.addLinesBuilder();
        lineBuilder.setLine(lineIdx);
        String s = revisionsByLine.get(lineIdx);
        if (StringUtils.isNotEmpty(s)) {
          lineBuilder.setScmRevision(s);
        }
        s = authorsByLine.get(lineIdx);
        if (StringUtils.isNotEmpty(s)) {
          lineBuilder.setScmAuthor(s);
        }
        s = datesByLine.get(lineIdx);
        if (StringUtils.isNotEmpty(s)) {
          lineBuilder.setScmDate(DateUtils.parseDateTime(s).getTime());
        }
        s = utHitsByLine.get(lineIdx);
        if (StringUtils.isNotEmpty(s)) {
          lineBuilder.setUtLineHits(Integer.parseInt(s));
        }
        s = utCondByLine.get(lineIdx);
        if (StringUtils.isNotEmpty(s)) {
          lineBuilder.setUtConditions(Integer.parseInt(s));
        }
        s = CharMatcher.anyOf(BOM).removeFrom(lines.get(lineIdx - 1));
        if (s != null) {
          lineBuilder.setSource(s);
        }

        // Free memory
        revisionsByLine.remove(lineIdx);
        authorsByLine.remove(lineIdx);
        datesByLine.remove(lineIdx);
        utHitsByLine.remove(lineIdx);
        utCondByLine.remove(lineIdx);
        utCoveredCondByLine.remove(lineIdx);
        itHitsByLine.remove(lineIdx);
        itCondByLine.remove(lineIdx);
        itCoveredCondByLine.remove(lineIdx);
        overallHitsByLine.remove(lineIdx);
        overallCondByLine.remove(lineIdx);
        overallCoveredCondByLine.remove(lineIdx);
        highlightingPerLine[lineIdx - 1] = null;
        symbolReferencesPerLine[lineIdx - 1] = null;
        duplicationsPerLine[lineIdx - 1] = null;
        lines.set(lineIdx - 1, null);
        lineBuilder.build();
      }
      return FileSourceDto.serializeData(dataBuilder.build());
    } catch (IOException e) {
      throw new IllegalStateException("Fail to read file " + file, e);
    }
  }

  private String[] computeDuplicationsPerLine(DefaultInputFile file, List<DuplicationGroup> duplicationGroups) {
    String[] result = new String[file.lines()];
    if (duplicationGroups == null) {
      return result;
    }
    List<DuplicationGroup> groups = new LinkedList<DuplicationGroup>(duplicationGroups);
    StringBuilder[] dupPerLine = new StringBuilder[file.lines()];
    int blockId = 1;
    for (Iterator<DuplicationGroup> it = groups.iterator(); it.hasNext();) {
      DuplicationGroup group = it.next();
      addBlock(blockId, group.originBlock(), dupPerLine);
      blockId++;
      for (Iterator<Block> dupsIt = group.duplicates().iterator(); dupsIt.hasNext();) {
        Block dups = dupsIt.next();
        if (dups.resourceKey().equals(file.key())) {
          addBlock(blockId, dups, dupPerLine);
          blockId++;
        }
        // Save memory
        dupsIt.remove();
      }
      // Save memory
      it.remove();
    }
    for (int i = 0; i < file.lines(); i++) {
      result[i] = dupPerLine[i] != null ? dupPerLine[i].toString() : null;
      // Save memory
      dupPerLine[i] = null;
    }
    return result;
  }

  private void addBlock(int blockId, Block block, StringBuilder[] dupPerLine) {
    int currentLine = block.startLine();
    for (int i = 0; i < block.length(); i++) {
      if (dupPerLine[currentLine - 1] == null) {
        dupPerLine[currentLine - 1] = new StringBuilder();
      }
      if (dupPerLine[currentLine - 1].length() > 0) {
        dupPerLine[currentLine - 1].append(',');
      }
      dupPerLine[currentLine - 1].append(blockId);
      currentLine++;
    }

  }

  @CheckForNull
  private SyntaxHighlightingData loadHighlighting(DefaultInputFile file) {
    SyntaxHighlightingData highlighting = componentDataCache.getData(file.key(), SnapshotDataTypes.SYNTAX_HIGHLIGHTING);
    String language = file.language();
    if (highlighting == null && language != null) {
      highlighting = codeColorizers.toSyntaxHighlighting(file.file(), file.encoding(), language);
    }
    return highlighting;
  }

  @CheckForNull
  private SymbolData loadSymbolReferences(DefaultInputFile file) {
    return componentDataCache.getData(file.key(), SnapshotDataTypes.SYMBOL_HIGHLIGHTING);
  }

  String[] computeHighlightingPerLine(DefaultInputFile file, @Nullable SyntaxHighlightingData highlighting) {
    String[] result = new String[file.lines()];
    if (highlighting == null) {
      return result;
    }
    Iterable<SyntaxHighlightingRule> rules = highlighting.syntaxHighlightingRuleSet();
    int currentLineIdx = 1;
    StringBuilder[] highlightingPerLine = new StringBuilder[file.lines()];
    for (SyntaxHighlightingRule rule : rules) {
      while (currentLineIdx < file.lines() && rule.getStartPosition() >= file.originalLineOffsets()[currentLineIdx]) {
        // This rule starts on another line so advance
        currentLineIdx++;
      }
      // Now we know current rule starts on current line
      writeDataPerLine(file.originalLineOffsets(), rule, rule.getStartPosition(), rule.getEndPosition(), highlightingPerLine, currentLineIdx, new RuleItemWriter());
    }
    for (int i = 0; i < file.lines(); i++) {
      result[i] = highlightingPerLine[i] != null ? highlightingPerLine[i].toString() : null;
    }
    return result;
  }

  String[] computeSymbolReferencesPerLine(DefaultInputFile file, @Nullable SymbolData symbolRefs) {
    String[] result = new String[file.lines()];
    if (symbolRefs == null) {
      return result;
    }
    StringBuilder[] symbolRefsPerLine = new StringBuilder[file.lines()];
    long[] originalLineOffsets = file.originalLineOffsets();
    int symbolId = 1;
    List<Symbol> symbols = new ArrayList<Symbol>(symbolRefs.referencesBySymbol().keySet());
    // Sort symbols to avoid false variation that would lead to an unnecessary update
    Collections.sort(symbols, new Comparator<Symbol>() {
      @Override
      public int compare(Symbol o1, Symbol o2) {
        return o1.getDeclarationStartOffset() - o2.getDeclarationStartOffset();
      }
    });
    for (Symbol symbol : symbols) {
      int declarationStartOffset = symbol.getDeclarationStartOffset();
      int declarationEndOffset = symbol.getDeclarationEndOffset();
      int length = declarationEndOffset - declarationStartOffset;
      addSymbol(symbolId, declarationStartOffset, declarationEndOffset, originalLineOffsets, symbolRefsPerLine);
      for (Integer referenceStartOffset : symbolRefs.referencesBySymbol().get(symbol)) {
        if (referenceStartOffset == declarationStartOffset) {
          // Ignore old API that used to store reference as first declaration
          continue;
        }
        addSymbol(symbolId, referenceStartOffset, referenceStartOffset + length, originalLineOffsets, symbolRefsPerLine);
      }
      symbolId++;
    }
    for (int i = 0; i < file.lines(); i++) {
      result[i] = symbolRefsPerLine[i] != null ? symbolRefsPerLine[i].toString() : null;
    }
    return result;
  }

  private void addSymbol(int symbolId, int startOffset, int endOffset, long[] originalLineOffsets, StringBuilder[] result) {
    int startLine = binarySearchLine(startOffset, originalLineOffsets);
    writeDataPerLine(originalLineOffsets, symbolId, startOffset, endOffset, result, startLine, new SymbolItemWriter());
  }

  private int binarySearchLine(int declarationStartOffset, long[] originalLineOffsets) {
    int begin = 0;
    int end = originalLineOffsets.length - 1;
    while (begin < end) {
      int mid = (int) Math.round((begin + end) / 2D);
      if (declarationStartOffset < originalLineOffsets[mid]) {
        end = mid - 1;
      } else {
        begin = mid;
      }
    }
    return begin + 1;
  }

  private <G> void writeDataPerLine(long[] originalLineOffsets, G item, int globalStartOffset, int globalEndOffset, StringBuilder[] dataPerLine, int startLine,
    RangeItemWriter<G> writer) {
    int currentLineIdx = startLine;
    // We know current item starts on current line
    long ruleStartOffsetCurrentLine = globalStartOffset;
    while (currentLineIdx < originalLineOffsets.length && globalEndOffset >= originalLineOffsets[currentLineIdx]) {
      // item continue on next line so write current line and continue on next line with same item
      writeItem(item, dataPerLine, currentLineIdx, ruleStartOffsetCurrentLine - originalLineOffsets[currentLineIdx - 1], originalLineOffsets[currentLineIdx]
        - originalLineOffsets[currentLineIdx - 1], writer);
      currentLineIdx++;
      ruleStartOffsetCurrentLine = originalLineOffsets[currentLineIdx - 1];
    }
    // item ends on current line
    writeItem(item, dataPerLine, currentLineIdx, ruleStartOffsetCurrentLine - originalLineOffsets[currentLineIdx - 1], globalEndOffset
      - originalLineOffsets[currentLineIdx - 1], writer);
  }

  private <G> void writeItem(G item, StringBuilder[] dataPerLine, int currentLineIdx, long startLineOffset, long endLineOffset, RangeItemWriter<G> writer) {
    if (startLineOffset == endLineOffset) {
      // Do not store empty items
      return;
    }
    if (dataPerLine[currentLineIdx - 1] == null) {
      dataPerLine[currentLineIdx - 1] = new StringBuilder();
    }
    StringBuilder currentLineSb = dataPerLine[currentLineIdx - 1];
    writer.writeItem(currentLineSb, startLineOffset, endLineOffset, item);
  }

  private static interface RangeItemWriter<G> {
    /**
     * Write item on a single line
     */
    void writeItem(StringBuilder currentLineSb, long startLineOffset, long endLineOffset, G item);
  }

  private static class RuleItemWriter implements RangeItemWriter<SyntaxHighlightingRule> {

    @Override
    public void writeItem(StringBuilder currentLineSb, long startLineOffset, long endLineOffset, SyntaxHighlightingRule item) {
      if (currentLineSb.length() > 0) {
        currentLineSb.append(SyntaxHighlightingData.RULE_SEPARATOR);
      }
      currentLineSb.append(startLineOffset)
        .append(SyntaxHighlightingData.FIELD_SEPARATOR)
        .append(endLineOffset)
        .append(SyntaxHighlightingData.FIELD_SEPARATOR)
        .append(item.getTextType().cssClass());
    }

  }

  private static class SymbolItemWriter implements RangeItemWriter<Integer> {

    @Override
    public void writeItem(StringBuilder currentLineSb, long startLineOffset, long endLineOffset, Integer symbolId) {
      if (currentLineSb.length() > 0) {
        currentLineSb.append(SymbolData.SYMBOL_SEPARATOR);
      }
      currentLineSb.append(startLineOffset)
        .append(SymbolData.FIELD_SEPARATOR)
        .append(endLineOffset)
        .append(SymbolData.FIELD_SEPARATOR)
        .append(symbolId);
    }

  }

  private Map<Integer, String> getLineMetric(DefaultInputFile file, String metricKey) {
    Map<Integer, String> authorsByLine;
    Iterator<Measure> authorsIt = measureCache.byMetric(file.key(), metricKey).iterator();
    if (authorsIt.hasNext()) {
      authorsByLine = KeyValueFormat.parseIntString((String) authorsIt.next().value());
    } else {
      authorsByLine = Collections.emptyMap();
    }
    return authorsByLine;
  }
}
