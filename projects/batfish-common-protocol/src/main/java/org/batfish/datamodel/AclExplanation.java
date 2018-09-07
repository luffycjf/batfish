package org.batfish.datamodel;

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Sets;
import java.util.Comparator;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.datamodel.acl.AndMatchExpr;
import org.batfish.datamodel.acl.FalseExpr;
import org.batfish.datamodel.acl.GenericAclLineMatchExprVisitor;
import org.batfish.datamodel.acl.MatchHeaderSpace;
import org.batfish.datamodel.acl.MatchSrcInterface;
import org.batfish.datamodel.acl.NotMatchExpr;
import org.batfish.datamodel.acl.OrMatchExpr;
import org.batfish.datamodel.acl.OriginatingFromDevice;
import org.batfish.datamodel.acl.PermittedByAcl;
import org.batfish.datamodel.acl.TrueExpr;

public class AclExplanation {
  private static enum Sources {
    INTERFACES,
    DEVICE,
    ANY
  }

  private boolean _satisfiable = true;

  private @Nullable HeaderSpace _headerSpace = null;

  private @Nullable SortedSet<HeaderSpace> _notHeaderSpaces = new TreeSet<>();

  private @Nonnull Sources _sources = Sources.ANY;

  private @Nullable Set<String> _sourceInterfaces = null;

  public boolean requireSourceInterfaces(Set<String> sourceInterfaces) {
    if (!_satisfiable) {
      return false;
    }
    if (_sources == Sources.DEVICE) {
      _satisfiable = false;
      return false;
    }
    _sources = Sources.INTERFACES;
    _sourceInterfaces =
        _sourceInterfaces == null
            ? sourceInterfaces
            : Sets.intersection(_sourceInterfaces, sourceInterfaces);
    _satisfiable = !_sourceInterfaces.isEmpty();
    return _satisfiable;
  }

  public boolean requireOriginatingFromDevice() {
    if (!_satisfiable) {
      return false;
    }
    if (_sources == Sources.INTERFACES) {
      _satisfiable = false;
      return false;
    }
    _sources = Sources.DEVICE;
    return true;
  }

  public boolean requireHeaderSpace(HeaderSpace headerSpace) {
    if (!_satisfiable) {
      return false;
    }
    if (_headerSpace == null) {
      _headerSpace = headerSpace;
      return true;
    }

    Optional<HeaderSpace> intersection = IntersectHeaderSpaces.intersect(_headerSpace, headerSpace);
    if (intersection.isPresent()) {
      _headerSpace = intersection.get();
    } else {
      _satisfiable = false;
    }
    return _satisfiable;
  }

  private boolean requireNotHeaderSpace(HeaderSpace headerSpace) {
    if (!_satisfiable) {
      return false;
    }
    _notHeaderSpaces.add(headerSpace);
    return true;
  }

  private Optional<AclLineMatchExpr> build() {
    if (!_satisfiable) {
      return Optional.empty();
    }

    ImmutableSortedSet.Builder<AclLineMatchExpr> conjunctsBuilder =
        new ImmutableSortedSet.Builder<>(Comparator.naturalOrder());
    if (_headerSpace != null) {
      conjunctsBuilder.add(new MatchHeaderSpace(_headerSpace));
    }
    _notHeaderSpaces.forEach(
        notHeaderSpace ->
            conjunctsBuilder.add(new NotMatchExpr(new MatchHeaderSpace(notHeaderSpace))));
    switch (_sources) {
      case DEVICE:
        conjunctsBuilder.add(OriginatingFromDevice.INSTANCE);
        break;
      case INTERFACES:
        conjunctsBuilder.add(new MatchSrcInterface(_sourceInterfaces));
        break;
      case ANY:
        break;
    }
    SortedSet<AclLineMatchExpr> conjuncts = conjunctsBuilder.build();
    if (conjuncts.isEmpty()) {
      return Optional.of(TrueExpr.INSTANCE);
    }
    if (conjuncts.size() == 1) {
      return Optional.of(conjuncts.first());
    }
    return Optional.of(new AndMatchExpr(conjuncts));
  }

  public static Optional<AclLineMatchExpr> explain(Iterable<AclLineMatchExpr> conjuncts) {
    AclExplanation explanation = new AclExplanation();

    conjuncts.forEach(
        expr ->
            expr.accept(
                new GenericAclLineMatchExprVisitor<Void>() {
                  @Override
                  public Void visitAndMatchExpr(AndMatchExpr andMatchExpr) {
                    throw new IllegalArgumentException(
                        "Can only explain normalized AclLineMatchExprs.");
                  }

                  @Override
                  public Void visitFalseExpr(FalseExpr falseExpr) {
                    throw new IllegalArgumentException(
                        "Can only explain satisfiable AclLineMatchExprs.");
                  }

                  @Override
                  public Void visitMatchHeaderSpace(MatchHeaderSpace matchHeaderSpace) {
                    explanation.requireHeaderSpace(matchHeaderSpace.getHeaderspace());
                    return null;
                  }

                  @Override
                  public Void visitMatchSrcInterface(MatchSrcInterface matchSrcInterface) {
                    explanation.requireSourceInterfaces(matchSrcInterface.getSrcInterfaces());
                    return null;
                  }

                  @Override
                  public Void visitNotMatchExpr(NotMatchExpr notMatchExpr) {
                    if (notMatchExpr.getOperand() instanceof MatchHeaderSpace) {
                      HeaderSpace headerSpace =
                          ((MatchHeaderSpace) notMatchExpr.getOperand()).getHeaderspace();
                      explanation.requireNotHeaderSpace(headerSpace);
                      return null;
                    }
                    throw new IllegalArgumentException(
                        "Can only explain normalized AclLineMatchExprs.");
                  }

                  @Override
                  public Void visitOriginatingFromDevice(
                      OriginatingFromDevice originatingFromDevice) {
                    explanation.requireOriginatingFromDevice();
                    return null;
                  }

                  @Override
                  public Void visitOrMatchExpr(OrMatchExpr orMatchExpr) {
                    throw new IllegalArgumentException(
                        "Can only explain normalized AclLineMatchExprs.");
                  }

                  @Override
                  public Void visitPermittedByAcl(PermittedByAcl permittedByAcl) {
                    throw new IllegalArgumentException(
                        "Can only explain normalized AclLineMatchExprs.");
                  }

                  @Override
                  public Void visitTrueExpr(TrueExpr trueExpr) {
                    // noop
                    return null;
                  }
                }));

    return explanation.build();
  }
}
