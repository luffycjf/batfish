package org.batfish.main;

import static org.batfish.datamodel.acl.AclLineMatchExprs.and;
import static org.batfish.datamodel.acl.AclLineMatchExprs.matchDst;
import static org.batfish.datamodel.acl.AclLineMatchExprs.not;
import static org.batfish.datamodel.acl.AclLineMatchExprs.or;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import com.google.common.collect.ImmutableList;
import org.batfish.datamodel.HeaderSpace;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.Prefix;
import org.batfish.datamodel.SubRange;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.datamodel.acl.MatchHeaderSpace;
import org.batfish.symbolic.bdd.BDDAcl;
import org.batfish.symbolic.bdd.BDDPacket;
import org.junit.Before;
import org.junit.Test;

public class TestAclExplanation {
  private BDDAcl _bddAcl;

  @Before
  public void setup() {
    BDDPacket pkt = new BDDPacket();
    _bddAcl = BDDAcl.create(pkt, IpAccessList.builder().setName("foo").build());
  }

  @Test
  public void testSimple() {
    AclLineMatchExpr expr =
        and(matchDst(Prefix.parse("1.2.3.0/24")), not(matchDst(new Ip("1.2.3.4"))));
    AclLineMatchExpr explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(expr));

    expr =
        and(
            matchDst(Prefix.parse("1.2.3.0/24")),
            or(matchDst(new Ip("1.2.3.4")), not(matchDst(new Ip("1.2.3.4")))));
    explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(matchDst(Prefix.parse("1.2.3.0/24"))));
  }

  @Test
  public void testNot() {
    MatchHeaderSpace matchDstIp = matchDst(new Ip("1.2.3.4"));
    MatchHeaderSpace matchDstPrefix = matchDst(Prefix.parse("1.2.3.0/24"));
    MatchHeaderSpace matchDstPort =
        new MatchHeaderSpace(
            HeaderSpace.builder().setDstPorts(ImmutableList.of(new SubRange(80, 80))).build());

    AclLineMatchExpr expr = not(and(matchDstIp, matchDstPrefix));
    AclLineMatchExpr explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(not(matchDstIp)));

    expr = not(or(matchDstIp, matchDstPrefix));
    explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(not(matchDstPrefix)));

    expr = not(and(matchDstIp, matchDstPort));
    explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(or(not(matchDstIp), not(matchDstPort))));

    expr = not(or(matchDstIp, matchDstPort));
    explanation = Batfish.explainAclExpr(_bddAcl, expr);
    assertThat(explanation, equalTo(and(not(matchDstIp), not(matchDstPort))));
  }
}
