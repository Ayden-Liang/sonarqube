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
package org.sonar.server.source.db;

import org.sonar.core.source.db.FileSourceDto;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Arrays;

public class FileSourceTesting {

  private FileSourceTesting() {
    // only static stuff
  }

  public static void updateDataColumn(Connection connection, String fileUuid, byte[] data) throws SQLException {
    PreparedStatement stmt = connection.prepareStatement("UPDATE file_sources SET binary_data = ? WHERE file_uuid=?");
    stmt.setBytes(1, data);
    stmt.setString(2, fileUuid);
    stmt.executeUpdate();
    stmt.close();
    connection.commit();
  }

  public static byte[] generateFakeData(int numberOfLines) throws IOException {
    FileSourceDb.Data.Builder dataBuilder = FileSourceDb.Data.newBuilder();
    for (int i = 1; i <= numberOfLines; i++) {
      dataBuilder.addLinesBuilder()
        .setLine(i)
        .setScmRevision("REVISION_" + i)
        .setScmAuthor("a_guy")
        .setScmDate(1500000000000L)
        .setSource("this is not java code " + i)
        .setUtLineHits(i)
        .setUtConditions(i + 1)
        .setUtCoveredConditions(i)
        .setItLineHits(i)
        .setItConditions(i + 1)
        .setItCoveredConditions(i)
        .setOverallLineHits(i)
        .setOverallConditions(i + 1)
        .setOverallCoveredConditions(i)
        .setHighlighting("2,9,k;9,18,k")
        .setSymbols("SYMBOLS")
        .addAllDuplications(Arrays.asList(19, 33, 141))
        .build();
    }
    return FileSourceDto.serializeData(dataBuilder.build());
  }
}
