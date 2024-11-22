--  WARNING! Timings side-channel vulns exist for this library
with Ada.Numerics.Big_Numbers.Big_Integers;
use Ada.Numerics.Big_Numbers.Big_Integers;

package X25519 is
   function Public_Key (Private_Key : Big_Integer) return Big_Integer;
end X25519;
