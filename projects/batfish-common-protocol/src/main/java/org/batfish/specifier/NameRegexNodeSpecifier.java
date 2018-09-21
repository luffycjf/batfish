package org.batfish.specifier;

import static java.util.Objects.requireNonNull;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** A {@link NodeSpecifier} that specifies the set of nodes whose names match the input regex. */
public final class NameRegexNodeSpecifier implements NodeSpecifier {
  private final Pattern _namePattern;

  public NameRegexNodeSpecifier(Pattern namePattern) {
    _namePattern = namePattern;
  }

  private static final String PROP_NAME_PATTERN = "namePattern";

  @JsonCreator
  private static @Nonnull NameRegexNodeSpecifier create(
      @JsonProperty(PROP_NAME_PATTERN) @Nullable String namePattern) {
    return new NameRegexNodeSpecifier(Pattern.compile(requireNonNull(namePattern)));
  }

  @JsonProperty(PROP_NAME_PATTERN)
  public @Nonnull String getNamePattern() {
    return _namePattern.pattern();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof NameRegexNodeSpecifier)) {
      return false;
    }
    NameRegexNodeSpecifier that = (NameRegexNodeSpecifier) o;
    return Objects.equals(_namePattern.pattern(), that._namePattern.pattern());
  }

  @Override
  public int hashCode() {
    return Objects.hash(_namePattern.pattern());
  }

  @Override
  public Set<String> resolve(SpecifierContext ctxt) {
    return ctxt.getConfigs()
        .keySet()
        .stream()
        .filter(n -> _namePattern.matcher(n).matches())
        .collect(ImmutableSet.toImmutableSet());
  }
}
