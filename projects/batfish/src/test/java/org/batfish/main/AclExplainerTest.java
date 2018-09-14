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
import java.util.List;
import org.batfish.common.bdd.BDDPacket;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpAccessListLine;
import org.batfish.datamodel.NetworkFactory;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.symbolic.bdd.BDDAcl;
import org.junit.Before;
import org.junit.Test;

public class AclExplainerTest {
  private static final Prefix PREFIX_32 = Prefix.parse("1.2.3.4/32");
  private static final Prefix PREFIX_24 = Prefix.parse("1.2.3.0/24");
  private static final Prefix PREFIX_16 = Prefix.parse("1.2.0.0/16");
  private static final Prefix PREFIX_8 = Prefix.parse("1.0.0.0/8");

  private BDDPacket _bddPacket;
  private NetworkFactory _nf;

  @Before
  public void setup() {
    _bddPacket = new BDDPacket();
    _nf = new NetworkFactory();
  }

  private AclExplainer explainer(IpAccessList acl) {
    BDDAcl bddAcl = BDDAcl.create(_bddPacket, acl);
    return new AclExplainer(bddAcl, acl, ImmutableMap.of());
  }

  @Test
  public void testDifferences() {
    IpAccessList acl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.rejecting().setMatchCondition(matchDst(PREFIX_32)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_24)).build(),
                    IpAccessListLine.rejecting().setMatchCondition(matchDst(PREFIX_16)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build()))
            .build();
    AclExplainer explainer = explainer(acl);

    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());

    assertThat(disjuncts, hasSize(2));

    assertThat(
        disjuncts,
        equalTo(
            ImmutableList.of(
                and(matchDst(PREFIX_24), not(matchDst(PREFIX_32))),
                and(
                    // match the prefix 8 line
                    matchDst(PREFIX_8),
                    // don't match the earlier rejecting lines
                    not(matchDst(PREFIX_16)),
                    not(matchDst(PREFIX_32))))));
  }

  @Test
  public void testDifferenceNonOverlapping() {
    Prefix nonOverlapping = Prefix.parse("8.0.0.0/8");
    IpAccessList acl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.rejecting()
                        .setMatchCondition(matchDst(nonOverlapping))
                        .build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build()))
            .build();
    AclExplainer explainer = explainer(acl);

    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());

    assertThat(disjuncts, hasSize(1));

    assertThat(disjuncts, equalTo(ImmutableList.of(matchDst(PREFIX_8))));
  }

  @Test
  public void testBlocked() {
    IpAccessList acl =
        _nf.aclBuilder()
            .setLines(
                ImmutableList.of(
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_8)).build(),
                    IpAccessListLine.accepting().setMatchCondition(matchDst(PREFIX_16)).build()))
            .build();
    AclExplainer explainer = explainer(acl);
    List<AclLineMatchExpr> disjuncts = explainer.explanationFor(_bddPacket.getFactory().one());
    assertThat(disjuncts, containsInAnyOrder(and(matchDst(PREFIX_8))));
  }
}
