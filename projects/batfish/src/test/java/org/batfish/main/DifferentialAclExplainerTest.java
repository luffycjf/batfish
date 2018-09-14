package org.batfish.main;

import static org.batfish.datamodel.acl.AclLineMatchExprs.and;
import static org.batfish.datamodel.acl.AclLineMatchExprs.matchDst;
import static org.batfish.datamodel.acl.AclLineMatchExprs.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.util.List;
import org.batfish.common.bdd.BDDPacket;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpAccessListLine;
import org.batfish.datamodel.NetworkFactory;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.symbolic.bdd.BDDAcl;
import org.batfish.symbolic.bdd.BDDSourceManager;
import org.junit.Before;
import org.junit.Test;

public class DifferentialAclExplainerTest {
  private static final Prefix PREFIX_32 = Prefix.parse("1.2.3.4/32");
  private static final Prefix PREFIX_24 = Prefix.parse("1.2.3.0/24");
  private static final Prefix PREFIX_16 = Prefix.parse("1.2.0.0/16");
  private static final Prefix PREFIX_8 = Prefix.parse("1.0.0.0/8");

  private BDDPacket _bddPacket;
  private NetworkFactory _nf;
  private BDDSourceManager _srcMgr;

  @Before
  public void setup() {
    _bddPacket = new BDDPacket();
    _nf = new NetworkFactory();
    _srcMgr = BDDSourceManager.forInterfaces(_bddPacket, ImmutableSet.of());
  }

  private DifferentialAclExplainer explainer(IpAccessList denyAcl, IpAccessList permitAcl) {
    BDDAcl denyBddAcl = BDDAcl.create(_bddPacket, denyAcl);
    BDDAcl permitBddAcl = BDDAcl.create(_bddPacket, denyAcl);
    return new DifferentialAclExplainer(
        denyBddAcl, denyAcl, ImmutableMap.of(), permitBddAcl, permitAcl, ImmutableMap.of());
  }

  @Test
  public void testDifferences() {
    IpAccessList denyAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.rejecting().setMatchCondition(matchDst(PREFIX_32)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_24)).build()))
            .build();
    IpAccessList permitAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.rejecting().setMatchCondition(matchDst(PREFIX_16)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build()))
            .build();
    DifferentialAclExplainer explainer = explainer(denyAcl, permitAcl);

    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());

    assertThat(disjuncts, hasSize(1));

    assertThat(
        disjuncts.get(0),
        equalTo(
            and(
                // match the prefix 8 line
                matchDst(PREFIX_8),
                // don't match the prefix 16 line
                not(matchDst(PREFIX_16)),
                // don't match the denyAcl.
                not(and(matchDst(PREFIX_24), not(matchDst(PREFIX_32)))))));
  }

  @Test
  public void testBlocked() {
    IpAccessList denyAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_16)).build()))
            .build();
    IpAccessList permitAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_24)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build()))
            .build();
    DifferentialAclExplainer explainer = explainer(denyAcl, permitAcl);
    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());
    assertThat(disjuncts, containsInAnyOrder(and(matchDst(PREFIX_8), not(matchDst(PREFIX_16)))));
  }

  @Test
  public void testPartiallyBlocked() {
    IpAccessList denyAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.rejecting().setMatchCondition(matchDst(PREFIX_24)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build()))
            .build();
    IpAccessList permitAcl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_32)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_16)).build()))
            .build();
    DifferentialAclExplainer explainer = explainer(denyAcl, permitAcl);
    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());
    assertThat(
        disjuncts,
        containsInAnyOrder(
            matchDst(PREFIX_32),
            // this simplifies to just matchDst(PREFIX_24)
            and(matchDst(PREFIX_16), matchDst(PREFIX_24))));
  }
}
