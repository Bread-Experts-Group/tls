package body X25519 is

   function Public_Key (Private_Key : Big_Integer) return Big_Integer is
   begin
      return (Private_Key**3) + (486_662 * (Private_Key**2)) + Private_Key;
   end Public_Key;

end X25519;
