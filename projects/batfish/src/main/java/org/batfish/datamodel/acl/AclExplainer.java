package org.batfish.datamodel.acl;

import static org.batfish.datamodel.IpAccessListLine.rejecting;
import static org.batfish.datamodel.acl.AclLineMatchExprNormalizer.normalize;
import static org.batfish.datamodel.acl.AclLineMatchExprs.and;
import static org.batfish.datamodel.acl.AclLineMatchExprs.not;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedSet;
import com.google.common.collect.Ordering;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.batfish.common.bdd.BDDPacket;
import org.batfish.common.bdd.BDDSourceManager;
import org.batfish.common.bdd.IpAccessListToBDD;
import org.batfish.common.bdd.MemoizedIpAccessListToBDD;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpAccessListLine;
import org.batfish.datamodel.IpSpace;
import org.batfish.datamodel.acl.normalize.AclToAclLineMatchExpr;
import org.batfish.z3.BDDIpAccessListSpecializer;
import org.batfish.z3.IpAccessListSpecializer;

/**
 * Generate an explanation of the headerspace permitted by an {@link IpAccessList}. The explanation
 * is a single {@link AclLineMatchExpr} in a simplified normal form. First we normalize to something
 * analogous to Disjunctive Normal Form, then simplify further if possible.
 */
public final class AclExplainer {
  private AclExplainer() {}

  /**
   * Explain the flow space permitted by one {@link IpAccessList} ({@param permitAcl}) but denied by
   * another ({@param denyAcl}). The {@param invariantExp} allows scoping the explanation to a space
   * of interest (use {@link TrueExpr} to explain the entire difference).
   */
  public static AclLineMatchExpr explainDifferential(
      BDDPacket bddPacket,
      BDDSourceManager mgr,
      AclLineMatchExpr invariantExpr,
      IpAccessList denyAcl,
      Map<String, IpAccessList> denyNamedAcls,
      Map<String, IpSpace> denyNamedIpSpaces,
      IpAccessList permitAcl,
      Map<String, IpAccessList> permitNamedAcls,
      Map<String, IpSpace> permitNamedIpSpaces) {
    // Construct an ACL that permits the difference of the two ACLs.
    DifferentialIpAccessList differentialIpAccessList =
        DifferentialIpAccessList.create(
            denyAcl,
            denyNamedAcls,
            denyNamedIpSpaces,
            permitAcl,
            permitNamedAcls,
            permitNamedIpSpaces);

    IpAccessListToBDD ipAccessListToBDD =
        MemoizedIpAccessListToBDD.create(
            bddPacket,
            mgr,
            differentialIpAccessList.getNamedAcls(),
            differentialIpAccessList.getNamedIpSpaces());

    return explain(
        mgr,
        ipAccessListToBDD,
        scopedAcl(invariantExpr, differentialIpAccessList.getAcl()),
        differentialIpAccessList.getNamedAcls(),
        differentialIpAccessList.getNamedIpSpaces());
  }

  /**
   * Explain the flow space permitted by an {@link IpAccessList}. The {@param invariantExp} allows
   * scoping the explanation to a space of interest (use {@link TrueExpr} to explain the entire
   * space).
   */
  public static AclLineMatchExpr explain(
      BDDPacket bddPacket,
      BDDSourceManager mgr,
      AclLineMatchExpr invariantExpr,
      IpAccessList acl,
      Map<String, IpAccessList> namedAcls,
      Map<String, IpSpace> namedIpSpaces) {
    IpAccessListToBDD ipAccessListToBDD =
        MemoizedIpAccessListToBDD.create(bddPacket, mgr, namedAcls, namedIpSpaces);

    IpAccessList aclWithInvariant = scopedAcl(invariantExpr, acl);

    return explain(mgr, ipAccessListToBDD, aclWithInvariant, namedAcls, namedIpSpaces);
  }

  private static AclLineMatchExpr explain(
      BDDSourceManager mgr,
      IpAccessListToBDD ipAccessListToBDD,
      IpAccessList acl,
      Map<String, IpAccessList> namedAcls,
      Map<String, IpSpace> namedIpSpaces) {
    // Convert acl to a single expression.
    AclLineMatchExpr aclExpr =
        AclToAclLineMatchExpr.toAclLineMatchExpr(ipAccessListToBDD, acl, namedAcls);

    // Reduce that expression to normal form.
    AclLineMatchExpr aclExprNf = normalize(ipAccessListToBDD, aclExpr);

    /*
     * Specialize each disjunct in the explanation to simplify further.
     */
    AclLineMatchExpr specializedNf =
        aclExprNf instanceof OrMatchExpr
            ? new OrMatchExpr(
                ((OrMatchExpr) aclExprNf)
                    .getDisjuncts()
                    .stream()
                    .map(expr -> specializeExplanation(ipAccessListToBDD, mgr, namedIpSpaces, expr))
                    .collect(ImmutableSortedSet.toImmutableSortedSet(Ordering.natural())))
            : specializeExplanation(ipAccessListToBDD, mgr, namedIpSpaces, aclExprNf);

    // return specializedNf;
    return AclExplanation.explainNormalForm(specializedNf);
  }

  @VisibleForTesting
  static AclLineMatchExpr specializeExplanation(
      IpAccessListToBDD ipAccessListToBDD,
      BDDSourceManager mgr,
      Map<String, IpSpace> namedIpSpaces,
      AclLineMatchExpr expr) {
    Set<AclLineMatchExpr> conjuncts =
        expr instanceof AndMatchExpr ? ((AndMatchExpr) expr).getConjuncts() : ImmutableSet.of(expr);

    Set<AclLineMatchExpr> positiveConjuncts =
        conjuncts
            .stream()
            .filter(conj -> !(conj instanceof NotMatchExpr))
            .collect(Collectors.toSet());
    Set<AclLineMatchExpr> negativeConjuncts =
        conjuncts.stream().filter(NotMatchExpr.class::isInstance).collect(Collectors.toSet());

    /*
     * First narrow the positive conjuncts to the space allowed by the negative conjuncts.
     */
    IpAccessListSpecializer specializer =
        new BDDIpAccessListSpecializer(
            ipAccessListToBDD.getBDDPacket(),
            ipAccessListToBDD.visit(and(negativeConjuncts)),
            namedIpSpaces,
            mgr,
            false);
    positiveConjuncts =
        positiveConjuncts.stream().map(specializer::visit).collect(Collectors.toSet());

    /*
     * Next, narrow the negative conjuncts to the space allowed by the positive conjuncts.
     */
    specializer =
        new BDDIpAccessListSpecializer(
            ipAccessListToBDD.getBDDPacket(),
            ipAccessListToBDD.visit(and(positiveConjuncts)),
            namedIpSpaces,
            mgr,
            true);
    negativeConjuncts =
        negativeConjuncts.stream().map(specializer::visit).collect(Collectors.toSet());

    /*
     * Now rebuild expr.
     */
    return new AndMatchExpr(
        ImmutableSortedSet.<AclLineMatchExpr>orderedBy(Ordering.natural())
            .addAll(positiveConjuncts)
            .addAll(negativeConjuncts)
            .build());
  }

  /**
   * Scope the headerspace permitted by an {@link IpAccessList} to those flows that also match
   * {@param invariantExpr}.
   */
  private static IpAccessList scopedAcl(AclLineMatchExpr invariantExpr, IpAccessList acl) {
    return IpAccessList.builder()
        .setName(acl.getName())
        .setLines(
            ImmutableList.<IpAccessListLine>builder()
                .add(rejecting(not(invariantExpr)))
                .addAll(acl.getLines())
                .build())
        .build();
  }
}
