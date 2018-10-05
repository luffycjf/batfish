package org.batfish.common.bdd;

import java.math.BigInteger;
import java.util.stream.IntStream;
import net.sf.javabdd.BDD;

/** Compute the cardinality of the set defined by a {@link BDD}. */
public final class BDDCardinality {
  private BDDCardinality() {}

  /** Compute the cardinality for a {@link BDD}. */
  public static BigInteger cardinality(BDD bdd) {
    return cardinality(bdd, bdd.getFactory().varNum());
  }

  /**
   * Compute the cardinality of the set defined by a {@link BDD} over a specified number of
   * variables.
   *
   * @param bdd The {@link BDD}.
   * @param vars The number of vars in scope (i.e. degrees of freedom). The cardinality of the
   *     universe (i.e. the {@link BDD} one) is 2 to the {@code vars} power.
   */
  public static BigInteger cardinality(BDD bdd, int vars) {
    return productLengths(bdd)
        .mapToObj(len -> BigInteger.valueOf(2).pow(vars - len))
        .reduce(BigInteger.ZERO, BigInteger::add);
  }

  /* Return the lengths of all products that comprise this BDD (i.e. paths to one) as a stream. */
  private static IntStream productLengths(BDD bdd) {
    return productLengths(bdd, 0);
  }

  private static IntStream productLengths(BDD bdd, int depth) {
    if (bdd.isZero()) {
      return IntStream.of();
    }
    if (bdd.isOne()) {
      return IntStream.of(depth);
    }
    int childDepth = depth + 1;
    return IntStream.concat(
        productLengths(bdd.high(), childDepth), productLengths(bdd.low(), childDepth));
  }
}
