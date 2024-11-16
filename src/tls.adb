with Ada.Text_IO;

package body TLS is

   function Wrap_Stream (Stream : Stream_Access) return Stream_Wrapper_Access is
   begin
      return new Stream_Wrapper'
          (TLS_Stream => new TLS_Stream_Type'(Root_Stream_Type with Raw_Stream => Stream),
           TLS_Active => False);
   end Wrap_Stream;

   function Stream (Wrapper : Stream_Wrapper) return Stream_Access is
   begin
      return Stream_Access (Wrapper.TLS_Stream);
   end Stream;

   function Stream_Raw (Wrapper : Stream_Wrapper) return Stream_Access is
   begin
      return Wrapper.TLS_Stream.Raw_Stream;
   end Stream_Raw;

   procedure Enable_TLS (Wrapper : in out Stream_Wrapper) is
   begin
      Wrapper.TLS_Active := True;
      --  TODO
   end Enable_TLS;

   procedure Disable_TLS (Wrapper : in out Stream_Wrapper) is
   begin
      Wrapper.TLS_Active := False;
      --  TODO
   end Disable_TLS;

   overriding
   procedure Read (Stream : in out TLS_Stream_Type; Item : out Stream_Element_Array; Last : out Stream_Element_Offset) is
   begin
      Stream.Raw_Stream.Read (Item, Last);
      --  TODO
   end Read;

   overriding
   procedure Write (Stream : in out TLS_Stream_Type; Item : Stream_Element_Array) is
   begin
      Stream.Raw_Stream.Write (Item);
      --  TODO
   end Write;

end TLS;
