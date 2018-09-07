package org.batfish.main;

import static org.batfish.datamodel.acl.AclLineMatchExprs.FALSE;
import static org.batfish.datamodel.acl.AclLineMatchExprs.TRUE;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import net.sf.javabdd.BDD;
import org.batfish.common.Pair;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.IpSpace;
import org.batfish.datamodel.LineAction;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.datamodel.acl.AclLineMatchExprs;
import org.batfish.datamodel.acl.TrueExpr;
import org.batfish.datamodel.acl.normalize.AclToAclLineMatchExpr;
import org.batfish.symbolic.bdd.AclLineMatchExprToBDD;
import org.batfish.symbolic.bdd.BDDAcl;
import org.batfish.symbolic.bdd.BDDPacket;
import org.batfish.symbolic.bdd.BDDSourceManager;
import org.batfish.symbolic.bdd.IpSpaceToBDD;
import org.batfish.z3.BDDIpAccessListSpecializer;

/**
 * Generates relatively easy-to-understand explanations of the set of packets permitted by an ACL.
 * The explanation is expressed as a list of {@link AclLineMatchExpr}, one per matching permit line.
 * The explanation of each permit line is of the form (matches line and doesn't match earlier deny
 * lines that intersect that space of the permit line). The client can specify a headerspace of
 * interest, and we will only include lines that intersect that space.
 */
public class AclExplainer {
  private final AclLineMatchExprToBDD _aclLineMatchExprToBDD;
  private final BDDPacket _bddPacket;
  private final Map<String, IpSpace> _ipSpaces;
  private final BDDSourceManager _mgr;

  private final List<Pair<LineAction, AclLineMatchExpr>> _aclLineExprs;
  private final IpSpaceToBDD _dstIpSpaceToBdd;
  private final IpSpaceToBDD _srcIpSpaceToBdd;

  public AclExplainer(BDDAcl bddAcl, IpAccessList acl, Map<String, IpAccessList> namedAcls) {
    _aclLineMatchExprToBDD = bddAcl.getAclLineMatchExprToBDD();
    _bddPacket = _aclLineMatchExprToBDD.getBDDPacket();
    _ipSpaces = _aclLineMatchExprToBDD.getIpSpaces();
    _dstIpSpaceToBdd = _aclLineMatchExprToBDD.getHeaderSpaceToBDD().getDstIpSpaceToBdd();
    _srcIpSpaceToBdd = _aclLineMatchExprToBDD.getHeaderSpaceToBDD().getSrcIpSpaceToBdd();
    _mgr = _aclLineMatchExprToBDD.getBDDSourceManager();
    _aclLineExprs = AclToAclLineMatchExpr.aclLines(_aclLineMatchExprToBDD, acl, namedAcls);
  }

  public List<AclLineMatchExpr> explanationFor(BDD headerSpaceBdd) {
    return explanationFor(headerSpaceBdd, false);
  }

  public List<AclLineMatchExpr> explanationFor(BDD headerSpaceBdd, boolean simplifyToTrue) {
    BDD reach = headerSpaceBdd.and(initialReachableHeaderSpace());

    List<AclLineMatchExpr> exprs = new ArrayList<>();

    for (int i = 0; !reach.isZero() && i < _aclLineExprs.size(); i++) {
      Pair<LineAction, AclLineMatchExpr> line = _aclLineExprs.get(i);
      BDD lineBdd = _aclLineMatchExprToBDD.visit(line.getSecond());
      BDD match = lineBdd.and(reach);
      if (line.getFirst() == LineAction.PERMIT && !match.isZero()) {
        exprs.add(permitLineExplanation(i, headerSpaceBdd, simplifyToTrue));
      }
      reach = reach.and(lineBdd.not());
    }

    return exprs;
  }

  protected BDD initialReachableHeaderSpace() {
    return _bddPacket.getFactory().one();
  }

  private AclLineMatchExpr permitLineExplanation(int i, BDD match, boolean simplifyToTrue) {
    // first, specialize the line to match
    AclLineMatchExpr lineExpr =
        new BDDIpAccessListSpecializer(
                _bddPacket,
                match,
                _ipSpaces,
                _mgr,
                _dstIpSpaceToBdd,
                _srcIpSpaceToBdd,
                simplifyToTrue)
            .visit(_aclLineExprs.get(i).getSecond());

    // only include reject lines that overlap with the specialized line expression.
    BDD lineExprBdd = _aclLineMatchExprToBDD.visit(lineExpr).and(match);
    BDDIpAccessListSpecializer specializer =
        new BDDIpAccessListSpecializer(
            _bddPacket,
            lineExprBdd,
            _ipSpaces,
            _mgr,
            _dstIpSpaceToBdd,
            _srcIpSpaceToBdd,
            simplifyToTrue);

    List<AclLineMatchExpr> conjuncts = new ArrayList<>();
    if (lineExpr != TrueExpr.INSTANCE) {
      conjuncts.add(lineExpr);
    }
    _aclLineExprs
        .stream()
        .limit(i)
        .filter(ln -> ln.getFirst() == LineAction.DENY)
        .map(Pair::getSecond)
        .map(specializer::visit)
        .map(AclLineMatchExprs::not)
        .filter(e -> e != TRUE)
        .forEach(conjuncts::add);
    extraLineExprs(lineExprBdd).forEach(conjuncts::add);
    return conjuncts.contains(FALSE) ? FALSE : AclLineMatchExprs.and(conjuncts);
  }

  protected Stream<AclLineMatchExpr> extraLineExprs(BDD bdd) {
    return Stream.of();
  }
}
