package org.batfish.main;

import static org.batfish.datamodel.acl.AclLineMatchExprs.TRUE;

import java.util.Map;
import java.util.stream.Stream;
import net.sf.javabdd.BDD;
import org.batfish.datamodel.IpAccessList;
import org.batfish.datamodel.acl.AclLineMatchExpr;
import org.batfish.datamodel.acl.AclLineMatchExprs;
import org.batfish.symbolic.bdd.BDDAcl;

/** Generates explanations of the difference between the headerspaces permitted by two ACLs. */
public final class DifferentialAclExplainer extends AclExplainer {
  private final BDDAcl _denyBddAcl;
  private final AclExplainer _denyExplainer;

  public DifferentialAclExplainer(
      BDDAcl denyBddAcl,
      IpAccessList denyAcl,
      Map<String, IpAccessList> denyAcls,
      BDDAcl permitBddAcl,
      IpAccessList permitAcl,
      Map<String, IpAccessList> permitAcls) {
    super(permitBddAcl, permitAcl, permitAcls);
    _denyBddAcl = denyBddAcl;
    _denyExplainer = new AclExplainer(denyBddAcl, denyAcl, denyAcls);
  }

  @Override
  protected BDD initialReachableHeaderSpace() {
    /*
     * Initialize the reachable header space to the packets denied by the deny ACL. Doing this means
     * we only include in the explanation those lines that permit packets denied by the deny ACL.
     */
    return _denyBddAcl.getBdd().not();
  }

  @Override
  protected Stream<AclLineMatchExpr> extraLineExprs(BDD bdd) {
    return _denyExplainer
        .explanationFor(bdd, true)
        .stream()
        .map(AclLineMatchExprs::not)
        .filter(e -> e != TRUE);
  }
}
