package org.batfish.bddreachability;

import com.google.common.collect.ImmutableSet;
import java.util.Set;
import org.batfish.common.BatfishException;
import org.batfish.z3.expr.StateExpr;
import org.batfish.z3.state.Accept;
import org.batfish.z3.state.Drop;
import org.batfish.z3.state.NeighborUnreachable;

/** Enumeration of the dispositions that {@link BDDReachabilityAnalysis} reasons about. */
public enum Disposition {
  /** {@link Accept} */
  ACCEPT,
  /** {@link Drop} */
  DROP,
  /** {@link NeighborUnreachable */
  NEIGHBOR_UNREACHABLE;

  public static final Set<Disposition> ALL_DISPOSITIONS =
      ImmutableSet.of(ACCEPT, DROP, NEIGHBOR_UNREACHABLE);

  public StateExpr toStateExpr() {
    switch (this) {
      case ACCEPT:
        return Accept.INSTANCE;
      case DROP:
        return Drop.INSTANCE;
      case NEIGHBOR_UNREACHABLE:
        return NeighborUnreachable.INSTANCE;
      default:
        throw new BatfishException("Unexpected Disposition: " + this.name());
    }
  }
}
