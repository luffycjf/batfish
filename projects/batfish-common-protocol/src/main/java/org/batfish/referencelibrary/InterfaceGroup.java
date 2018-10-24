package org.batfish.referencelibrary;

import static com.google.common.base.MoreObjects.firstNonNull;
import static com.google.common.base.Preconditions.checkArgument;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.batfish.datamodel.collections.NodeInterfacePair;

public class InterfaceGroup implements Comparable<InterfaceGroup> {

  private static final String PROP_INTERFACES = "interfaces";
  private static final String PROP_NAME = "name";

  @Nonnull private SortedSet<NodeInterfacePair> _interfaces;
  @Nonnull private String _name;

  public InterfaceGroup(
      @Nullable @JsonProperty(PROP_INTERFACES) SortedSet<NodeInterfacePair> interfaces,
      @Nullable @JsonProperty(PROP_NAME) String name) {
    checkArgument(name != null, "Interface group name cannot not be null");
    ReferenceLibrary.checkValidName(name, "interface group");

    _name = name;
    _interfaces = firstNonNull(interfaces, new TreeSet<>());
  }

  @Override
  public int compareTo(InterfaceGroup o) {
    return _name.compareTo(o._name);
  }

  @JsonProperty(PROP_INTERFACES)
  @Nonnull
  public SortedSet<NodeInterfacePair> getInterfaces() {
    return _interfaces;
  }

  @JsonProperty(PROP_NAME)
  @Nonnull
  public String getName() {
    return _name;
  }
}
