package org.batfish.common.bdd;

import java.math.BigInteger;
import java.util.stream.Stream;
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
    return products(bdd)
        .map(path -> productCardinality(path, vars))
        .reduce(BigInteger.ZERO, BigInteger::add);
  }

  private static BigInteger productCardinality(BDD product, int vars) {
    return BigInteger.valueOf(2).pow(vars - productLength(product));
  }

  /**
   * @param product A conjunction of {@link BDD} literals (positive or negative variables). I.e. a
   *     {@link BDD} with exactly 1 path from the root to the 1 node.
   * @return The number of edges from the root to the one node.
   */
  private static int productLength(BDD product) {
    if (product.isOne()) {
      return 0;
    }
    return product.high().isZero()
        ? productLength(product.low()) + 1
        : productLength(product.high()) + 1;
  }

  /**
   * A product in boolean logic is a conjunction of literals (positive or negative variables). A
   * {@link BDD} product has only one path from the root to the one node. Any logical formula can be
   * normalized to CNF (a disjuction of products). This function does essentially the same thing for
   * {@link BDD BDDs} -- it decomposes the input {@link BDD} into a disjunction of products, and
   * returns a stream of those products.
   */
  private static Stream<BDD> products(BDD bdd) {
    if (bdd.isZero()) {
      return Stream.of();
    }
    if (bdd.isOne()) {
      return Stream.of(bdd);
    }
    BDD var = bdd.getFactory().ithVar(bdd.var());
    BDD notVar = var.not();
    return Stream.concat(products(bdd.high()).map(var::and), products(bdd.low()).map(notVar::and));
  }
}
