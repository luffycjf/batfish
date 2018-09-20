package org.batfish.datamodel.table;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkArgument;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.annotation.ParametersAreNonnullByDefault;
import org.batfish.common.BatfishException;
import org.batfish.common.util.BatfishObjectMapper;
import org.batfish.datamodel.Flow;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.answers.Issue;
import org.batfish.datamodel.answers.Schema;
import org.batfish.datamodel.answers.SchemaUtils;
import org.batfish.datamodel.collections.FileLines;
import org.batfish.datamodel.collections.NodeInterfacePair;
import org.batfish.datamodel.pojo.Node;
import org.batfish.datamodel.questions.Exclusion;

/**
 * Represents one row of the table answer. Each row is basically a map of key value pairs, where the
 * key is the column name and the value (currently) is JsonNode.
 */
@ParametersAreNonnullByDefault
public class Row implements Comparable<Row>, Serializable {

  private static final long serialVersionUID = 1L;

  public static class RowBuilder {

    private final Map<String, Object> _data;

    private RowBuilder(Map<String, ColumnMetadata> columns) {
      _columns = columns;
      _data = new HashMap<>();
    }

    public Row build() {
      return new Row(ImmutableMap.copyOf(_columns), ImmutableMap.copyOf(_data));
    }

    @VisibleForTesting
    @Nonnull
    Row rowOf(Object... objects) {
      checkArgument(
          objects.length % 2 == 0,
          "expecting an even number of parameters, not %s",
          objects.length);
      for (int i = 0; i + 1 < objects.length; i += 2) {
        checkArgument(
            objects[i] instanceof String,
            "argument %s must be a string, but is: %s",
            i,
            objects[i]);
        put((String) objects[i], objects[i + 1]);
      }
      return build();
    }


    /** Mirrors the values of all columns in {@code otherRow} */
    public RowBuilder putAll(Row otherRow) {
      return putAll(otherRow, otherRow.getColumnNames());
    }

    /**
     * Mirrors the values of {@code columns} in {@code otherRow}
     *
     * @throws NoSuchElementException if one of the columns is not present in {@code otherRow}.
     */
    public RowBuilder putAll(Row otherRow, Collection<String> columns) {
      columns.forEach(col -> put(col, otherRow.get(col)));
      return this;
    }

    Map<String, ColumnMetadata> _columns;

    /**
     * Puts {@code object} into column {@code column} of the row, after checking if the object is
     * compatible with the Schema of the column
     */
    public RowBuilder put(String column, @Nullable Object value) {
      checkArgument(
          _columns.containsKey(column), Row.missingColumnErrorMessage(column, _columns.keySet()));
      Schema expectedSchema = _columns.get(column).getSchema();
      checkArgument(
          SchemaUtils.isValidObject(value, expectedSchema),
          String.format(
              "Cannot convert '%s' to Schema '%s' of column '%s", value, expectedSchema, column));
      _data.put(column, value);
      return this;
    }
  }

  /**
   * Returns a new {@link Row} with the given entries.
   *
   * <p>{@code objects} should be an even number of parameters, where the 0th and every even
   * parameter is a {@link String} representing the name of a column. The columns names and the
   * actual objects (in odd parameters) must be compliant with the metadata map in {@code columns}.
   */
  public static Row of(Map<String, ColumnMetadata> columns, Object... objects) {
    return builder(columns).rowOf(objects);
  }

  /** Returns a {@link RowBuilder} object for Row */
  public static RowBuilder builder(Map<String, ColumnMetadata> columns) {
    return new RowBuilder(columns);
  }

  /**
   * Compares two Rows. The current implementation ignores primary keys of the table and compares
   * everything, mainly to provide consistent ordering of answers. This will need to change when we
   * start using the primary keys for something.
   *
   * @param o The other Row to compare against.
   * @return The result of the comparison
   */
  @Override
  public int compareTo(Row o) {
    try {
      String myStr = BatfishObjectMapper.mapper().writeValueAsString(_data);
      String oStr = BatfishObjectMapper.mapper().writeValueAsString(o._data);
      return myStr.compareTo(oStr);
    } catch (JsonProcessingException e) {
      throw new BatfishException("Exception in row comparison", e);
    }
  }

  private final Map<String, Object> _data;

  private final Map<String, ColumnMetadata> _columnMetadata;

  private Row(Map<String, ColumnMetadata> columnMetadata, Map<String, Object> data) {
    _columnMetadata = columnMetadata;
    _data = data;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof Row)) {
      return false;
    }
    Row rhs = (Row) o;
    return _columnMetadata.equals(rhs._columnMetadata) && _data.equals(rhs._data);
  }

  /**
   * Gets the (raw) Json representation of the object stored in the row
   *
   * @param columnName The column to fetch
   * @return The {@link JsonNode} object that represents the stored object
   * @throws NoSuchElementException if this column does not exist
   */
  public @Nullable Object get(String columnName) {
    if (!_data.containsKey(columnName)) {
      throw new NoSuchElementException(missingColumnErrorMessage(columnName, getColumnNames()));
    }
    return _data.get(columnName);
  }

  /**
   * Gets the value of specified column
   *
   * @param column The column to fetch
   * @param schema A compatible Schema by which the value may be represented
   * @return The result
   * @throws NoSuchElementException if this column is not present
   * @throws ClassCastException if the recovered data cannot be cast to the expected object
   */
  private Object get(String column, Schema schema) {
    if (!_data.containsKey(column)) {
      throw new NoSuchElementException(missingColumnErrorMessage(column, getColumnNames()));
    }
    if (_data.get(column) == null) {
      return null;
    }
    return SchemaUtils.convertType(_data.get(column), schema);
  }

  public Boolean getBoolean(String column) {
    return (Boolean) get(column, Schema.BOOLEAN);
  }

  /**
   * Fetch the names of the columns in this Row
   *
   * @return The {@link Set} of names
   */
  public Set<String> getColumnNames() {
    return _columnMetadata.keySet();
  }

  public Double getDouble(String column) {
    return (Double) get(column, Schema.DOUBLE);
  }

  public FileLines getFileLines(String column) {
    return (FileLines) get(column, Schema.FILE_LINES);
  }

  public Flow getFlow(String column) {
    return (Flow) get(column, Schema.FLOW);
  }

  public Integer getInteger(String column) {
    return (Integer) get(column, Schema.INTEGER);
  }

  /**
   * Returns the list of values in all columns declared as key in the metadata.
   *
   * @param metadata Provides information on which columns are key and their {@link Schema}
   * @return The list
   */
  public List<Object> getKey(List<ColumnMetadata> metadata) {
    List<Object> keyList = new LinkedList<>();
    for (ColumnMetadata column : metadata) {
      if (column.getIsKey()) {
        keyList.add(get(column.getName(), column.getSchema()));
      }
    }
    return keyList;
  }

  @JsonCreator
  private static Row forbidJacksonDeserialization(Object o) {
    throw new UnsupportedOperationException(
        String.format(
            "%s not intended to be deserialized via Jackson", Row.class.getCanonicalName()));
  }

  @JsonValue
  private static Object forbidJacksonSerialization() {
    throw new UnsupportedOperationException(
        String.format(
            "%s not intended to be serialized via Jackson", Row.class.getCanonicalName()));
  }

  /** This used to be the old signature, changed now to {@link #getKey(List)} */
  @Deprecated
  public List<Object> getKey(TableMetadata metadata) {
    return getKey(metadata.getColumnMetadata());
  }

  public NodeInterfacePair getInterface(String column) {
    return (NodeInterfacePair) get(column, Schema.INTERFACE);
  }

  public Ip getIp(String column) {
    return (Ip) get(column, Schema.IP);
  }

  public Issue getIssue(String column) {
    return (Issue) get(column, Schema.ISSUE);
  }

  public Node getNode(String column) {
    return (Node) get(column, Schema.NODE);
  }

  public Object getObject(String column) {
    return get(column, Schema.OBJECT);
  }

  public Prefix getPrefix(String column) {
    return (Prefix) get(column, Schema.PREFIX);
  }

  public String getString(String column) {
    return (String) get(column, Schema.STRING);
  }

  /**
   * Returns the list of values in all columns declared as value in the metadata.
   *
   * @param metadata Provides information on which columns are key and their {@link Schema}
   * @return The list
   */
  public List<Object> getValue(List<ColumnMetadata> metadata) {
    List<Object> valueList = new LinkedList<>();
    for (ColumnMetadata column : metadata) {
      if (column.getIsValue()) {
        valueList.add(get(column.getName(), column.getSchema()));
      }
    }
    return valueList;
  }

  /** This used to be the old signature, changed now to {@link #getValue(List)} */
  @Deprecated
  public List<Object> getValue(TableMetadata metadata) {
    return getValue(metadata.getColumnMetadata());
  }

  @Override
  public int hashCode() {
    return Objects.hash(_data);
  }

  /**
   * Checks is this row is covered by the provided exclusion.
   *
   * @param exclusion The exclusion to check against.
   * @return The result of the check
   */
  public boolean isCovered(Map<String, Object> exclusion) {
    return Exclusion.firstCoversSecond(exclusion, _data);
  }

  /** Returns a message indicating that {@code columnName} is not present in {@code columns} */
  public static String missingColumnErrorMessage(String columnName, Set<String> columns) {
    return String.format("Column '%s' is not present. Valid columns are: %s", columnName, columns);
  }

  @Override
  public String toString() {
    return _data.toString();
  }
}
