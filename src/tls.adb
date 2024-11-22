with Ada.Text_IO;
with Ada.Unchecked_Conversion;

with ByteFlip;

with Random;

package body TLS is
   ------------------------
   -- TLS Stream/Wrapper --
   -- Operations         --
   ------------------------

   function Wrap_Stream (Stream : Stream_Access) return TLS_Stream_Access is
   begin
      return new TLS_Stream_Type'
          (Root_Stream_Type with Raw_Stream => Stream,
           TLS_Active                       => False);
   end Wrap_Stream;

   function Stream (TLS_Stream : TLS_Stream_Access) return Stream_Access is
   begin
      return Stream_Access (TLS_Stream);
   end Stream;

   function Stream_Raw (TLS_Stream : TLS_Stream_Access) return Stream_Access is
   begin
      return TLS_Stream.Raw_Stream;
   end Stream_Raw;

   procedure Enable_TLS (TLS_Stream : in out TLS_Stream_Access) is

      Client_Hello_Rec : Handshake_Client_Hello_Record;
      Server_Hello_Rec : Handshake_Server_Hello_Record;

   begin
      if TLS_Stream.TLS_Active
      then
         raise TLS_State_Error with "TLS is already enabled";

      else
         Handshake_Client_Hello_Record'Read (TLS_Stream.Raw_Stream, Client_Hello_Rec);
         Ada.Text_IO.Put_Line (Client_Hello_Rec'Image);

         Server_Hello_Rec.Record_Type  := HANDSHAKE;
         Server_Hello_Rec.Message_Type := SERVER_HELLO;

         Random.Fill (Server_Hello_Rec.Server_Random);
         Server_Hello_Rec.Server_Session_ID   := Client_Hello_Rec.Client_Session_ID;
         Server_Hello_Rec.Server_Cipher_Suite := Client_Hello_Rec.Client_Cipher_Suites.Element (1);
         Server_Hello_Rec.Server_Extensions.Append
           (Extension'
              (Extension_Type => SUPPORTED_VERSIONS,
               Versions       => Protocol_Versions_Array_Holders.To_Holder ([TLS_13]),
               others         => <>));
               --  Server_Hello_Rec.Server_Extensions.Append
               --    (Extension'
               --       (Extension_Type => KEY_SHARE,
               --        others         => <>));

         Handshake_Server_Hello_Record'Write (TLS_Stream.Raw_Stream, Server_Hello_Rec);

         TLS_Stream.TLS_Active := True;
      end if;
   end Enable_TLS;

   procedure Disable_TLS (TLS_Stream : in out TLS_Stream_Access) is
   begin
      if TLS_Stream.TLS_Active
      then
         TLS_Stream.TLS_Active := False;
         raise Program_Error with "Disable";

      else
         raise TLS_State_Error with "TLS is already disabled";
      end if;
   end Disable_TLS;

   ----------------------------
   -- TLS Record Stream Ops. --
   ----------------------------

   ----------------
   -- TLS_Record --
   ----------------

   --  Unsigned_16 Stream Management

   package U16_Byteflipper is new ByteFlip (Unsigned_16);

   type U16S is new String (1 .. 2);

   procedure Write_Unsigned_16 (Stream : not null access Root_Stream_Type'Class; Item : Unsigned_16) is

      function U16_To_S2 is new Ada.Unchecked_Conversion (Unsigned_16, U16S);
      U16 : Unsigned_16 := Item;

   begin
      U16_Byteflipper.Flip_Big_Endian_Bytes (U16);
      U16S'Write (Stream, U16_To_S2 (U16));
   end Write_Unsigned_16;

   procedure Read_Unsigned_16 (Stream : not null access Root_Stream_Type'Class; Item : out Unsigned_16) is

      function S2_To_U16 is new Ada.Unchecked_Conversion (U16S, Unsigned_16);
      Data : U16S;

   begin
      U16S'Read (Stream, Data);
      Item := S2_To_U16 (Data);
      U16_Byteflipper.Flip_Big_Endian_Bytes (Item);
   end Read_Unsigned_16;

      --  Protocol_Versions Stream Management

   procedure Write_Protocol_Version (Stream : not null access Root_Stream_Type'Class; Item : Protocol_Versions) is

      function PV_To_U16 is new Ada.Unchecked_Conversion (Protocol_Versions, Unsigned_16);

   begin
      Unsigned_16'Write (Stream, PV_To_U16 (Item));
   end Write_Protocol_Version;

   procedure Read_Protocol_Version (Stream : not null access Root_Stream_Type'Class; Item : out Protocol_Versions) is

      function U16_To_PV is new Ada.Unchecked_Conversion (Unsigned_16, Protocol_Versions);
      Version : Protocol_Versions := U16_To_PV (Unsigned_16'Input (Stream));

   begin
      Item := (if Version'Valid then Version else UNKNOWN);
   end Read_Protocol_Version;

   --  TLS_Record Stream Management

   procedure Write_TLS_Record (Stream : not null access Root_Stream_Type'Class; Item : TLS_Record) is
   begin
      Record_Types'Write (Stream, Item.Record_Type);
      Unsigned_16'Write (Stream, Protocol_Versions'Enum_Rep (Item.Record_Protocol_Version));
      Unsigned_16'Write (Stream, Item.Record_Length);
   end Write_TLS_Record;

   procedure Read_TLS_Record (Stream : not null access Root_Stream_Type'Class; Item : out TLS_Record) is
   begin
      Record_Types'Read (Stream, Item.Record_Type);
      Protocol_Versions'Read (Stream, Item.Record_Protocol_Version);
      Unsigned_16'Read (Stream, Item.Record_Length);
   end Read_TLS_Record;

   ----------------------
   -- Handshake_Record --
   ----------------------

   --  Unsigned_24 Stream Management

   package U24_Byteflipper is new ByteFlip (Unsigned_24);

   type U24S is new String (1 .. 3);

   procedure Write_Unsigned_24 (Stream : not null access Root_Stream_Type'Class; Item : Unsigned_24) is

      function U24_To_S3 is new Ada.Unchecked_Conversion (Unsigned_24, U24S);
      U24 : Unsigned_24 := Item;

   begin
      U24_Byteflipper.Flip_Big_Endian_Bytes (U24);
      U24S'Write (Stream, U24_To_S3 (U24));
   end Write_Unsigned_24;

   procedure Read_Unsigned_24 (Stream : not null access Root_Stream_Type'Class; Item : out Unsigned_24) is

      function S3_To_U24 is new Ada.Unchecked_Conversion (U24S, Unsigned_24);
      Data : U24S;

   begin
      U24S'Read (Stream, Data);
      Item := S3_To_U24 (Data);
      U24_Byteflipper.Flip_Big_Endian_Bytes (Item);
   end Read_Unsigned_24;

   --  Handshake_Record Stream Management

   procedure Write_Handshake_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Record) is
   begin
      Write_TLS_Record (Stream, Item);
      Handshake_Message_Types'Write (Stream, Item.Message_Type);
      Unsigned_24'Write (Stream, Item.Message_Length);
   end Write_Handshake_Record;

   procedure Read_Handshake_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Record) is
   begin
      Read_TLS_Record (Stream, Item);
      Handshake_Message_Types'Read (Stream, Item.Message_Type);
      Unsigned_24'Read (Stream, Item.Message_Length);
   end Read_Handshake_Record;

      -----------------------------------
      -- Handshake_Client_Hello_Record --
      -----------------------------------

      --  Cipher_Suites Stream Management

   procedure Write_Cipher_Suite (Stream : not null access Root_Stream_Type'Class; Item : Cipher_Suites) is

      function CS_To_U16 is new Ada.Unchecked_Conversion (Cipher_Suites, Unsigned_16);

   begin
      Unsigned_16'Write (Stream, CS_To_U16 (Item));
   end Write_Cipher_Suite;

   procedure Read_Cipher_Suite (Stream : not null access Root_Stream_Type'Class; Item : out Cipher_Suites) is

      function U16_To_CS is new Ada.Unchecked_Conversion (Unsigned_16, Cipher_Suites);
      Suite : Cipher_Suites := U16_To_CS (Unsigned_16'Input (Stream));

   begin
      Item := (if Suite'Valid then Suite else Cipher_Suites'(UNKNOWN));
   end Read_Cipher_Suite;

      --  Compression_Methods Stream Management

   procedure Read_Compression_Method (Stream : not null access Root_Stream_Type'Class; Item : out Compression_Methods) is

      function U8_To_CM is new Ada.Unchecked_Conversion (Unsigned_8, Compression_Methods);
      Method : Compression_Methods := U8_To_CM (Unsigned_8'Input (Stream));

   begin
      Item := (if Method'Valid then Method else Compression_Methods'(UNKNOWN));
   end Read_Compression_Method;

      --  Elliptic_Curve_Groups Stream Management

   procedure Write_Elliptic_Curve_Group (Stream : not null access Root_Stream_Type'Class; Item : Elliptic_Curve_Groups) is

      function ECG_To_U16 is new Ada.Unchecked_Conversion (Elliptic_Curve_Groups, Unsigned_16);

   begin
      Unsigned_16'Write (Stream, ECG_To_U16 (Item));
   end Write_Elliptic_Curve_Group;

   procedure Read_Elliptic_Curve_Group (Stream : not null access Root_Stream_Type'Class; Item : out Elliptic_Curve_Groups) is

      function U16_To_ECG is new Ada.Unchecked_Conversion (Unsigned_16, Elliptic_Curve_Groups);
      Group : Elliptic_Curve_Groups := U16_To_ECG (Unsigned_16'Input (Stream));

   begin
      Item := (if Group'Valid then Group else Elliptic_Curve_Groups'(UNKNOWN));
   end Read_Elliptic_Curve_Group;

   --  Extension Stream Management

   procedure Assign_Extension_Size (Item : in out Extension) is
   begin
      case Item.Extension_Type is
         when KEY_SHARE =>
            --  Item.Size := 4 + Item.Public_Key.Element'Length;
            raise Program_Error with ":?";

         when SUPPORTED_VERSIONS =>
            if Item.From_Server
            then
               Item.Size := 2;

            else
               Item.Size := 1 + (Item.Versions.Element'Length * 2);
            end if;

         when others =>
            Item.Size := Item.Data.Element'Length;
      end case;
   end Assign_Extension_Size;

   procedure Write_Extension (Stream : not null access Root_Stream_Type'Class; Item : Extension) is

      This_Extension : Extension := Item;

   begin
      Unsigned_16'Write
        (Stream, (if This_Extension.Assigned_Value = Extension_Types'(UNKNOWN)'Enum_Rep then This_Extension.Extension_Type'Enum_Rep else This_Extension.Assigned_Value));

      if not This_Extension.Size_Assigned
      then
         Assign_Extension_Size (This_Extension);
      end if;
      Unsigned_16'Write (Stream, This_Extension.Size);

      case This_Extension.Extension_Type is
         when KEY_SHARE =>
            if This_Extension.From_Server
            then
               raise Program_Error with ":3";

            else
               raise Program_Error with "TODO";
               --  Elliptic_Curve_Groups'Write (Stream, This_Extension.Curve);
               --  Unsigned_16'Write (Stream, This_Extension.Public_Key.Element'Length);
               --  String'Write (Stream, This_Extension.Public_Key.Element);
            end if;

         when SUPPORTED_VERSIONS =>
            if This_Extension.From_Server
            then
               Protocol_Versions'Write (Stream, This_Extension.Versions.Element (1));

            else
               Unsigned_8'Write (Stream, This_Extension.Versions.Element'Length * 2);
               Protocol_Versions_Array'Write (Stream, This_Extension.Versions.Element);
            end if;

         when others =>
            String'Write (Stream, This_Extension.Data.Element);
      end case;
   end Write_Extension;

   procedure Read_Extension (Stream : not null access Root_Stream_Type'Class; Item : out Extension) is

      Length : Unsigned_16 := Unsigned_16'Input (Stream);

   begin
      case Item.Extension_Type is
         when KEY_SHARE =>
            if Item.From_Server
            then
               raise Program_Error with "meow";
               --  declare

               --     Assigned_Curve : Elliptic_Curve_Groups := Elliptic_Curve_Groups'Input (Stream);
               --     Public_Key     : String (1 .. Integer (Unsigned_16'Input (Stream)));

               --  begin
               --     Item.Curve := Assigned_Curve;
               --     String'Read (Stream, Public_Key);
               --     Item.Public_Key := String_Holders.To_Holder (Public_Key);
               --  end;

            else
               raise Program_Error with ":<";
            end if;

         when SUPPORTED_VERSIONS =>
            if Item.From_Server
            then
               Item.Versions := Protocol_Versions_Array_Holders.To_Holder (Protocol_Versions_Array'[Protocol_Versions'Input (Stream)]);

            else
               declare

                  Versions : Protocol_Versions_Array (1 .. Integer (Unsigned_8'Input (Stream)) / 2);

               begin
                  Protocol_Versions_Array'Read (Stream, Versions);
                  Item.Versions := Protocol_Versions_Array_Holders.To_Holder (Versions);
               end;
            end if;

         when others =>
            declare

               Data : String (1 .. Integer (Length));

            begin
               String'Read (Stream, Data);
               Item.Data := String_Holders.To_Holder (Data);
            end;
      end case;
      Item.Size          := Length;
      Item.Size_Assigned := True;
   end Read_Extension;

   function Read_Extension (Stream : not null access Root_Stream_Type'Class) return Extension is

      function U16_To_ET is new Ada.Unchecked_Conversion (Unsigned_16, Extension_Types);
      Assigned_Type_Raw : constant Unsigned_16     := Unsigned_16'Input (Stream);
      Assigned_Type     : constant Extension_Types := U16_To_ET (Assigned_Type_Raw);
      New_Extension     : Extension (if Assigned_Type'Valid then Assigned_Type else UNKNOWN);

   begin
      New_Extension.Assigned_Value := Assigned_Type_Raw;
      Extension'Read (Stream, New_Extension);
      return New_Extension;
   end Read_Extension;

   --  Handshake_Client_Hello_Record Stream Management

   --  procedure Write_Handshake_Client_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Client_Hello_Record) is
   --  begin
   --     --  TODO
   --     Write_Handshake_Record (Stream, Item);
   --  end Write_Handshake_Client_Hello_Record;

   procedure Read_Handshake_Client_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Client_Hello_Record) is
   begin
      Read_Handshake_Record (Stream, Item);
      Protocol_Versions'Read (Stream, Item.Client_Protocol_Version);
      String'Read (Stream, Item.Client_Random);

      declare

         Data : String (1 .. Integer (Unsigned_8'Input (Stream)));

      begin
         String'Read (Stream, Data);
         Item.Client_Session_ID := String_Holders.To_Holder (Data);
      end;

      declare

         Data : Cipher_Suite_Array (1 .. Unsigned_16'Input (Stream) / 2);

      begin
         Cipher_Suite_Array'Read (Stream, Data);
         Item.Client_Cipher_Suites := Cipher_Suite_Holders.To_Holder (Data);
      end;

      declare

         Data : Compression_Method_Array (1 .. Unsigned_8'Input (Stream));

      begin
         Compression_Method_Array'Read (Stream, Data);
         Item.Client_Compression_Methods := Compression_Method_Holders.To_Holder (Data);
      end;

      Unsigned_16'Read (Stream, Item.Extensions_Length);

      declare

         Position : Unsigned_16 := 0;

      begin
         loop
            declare

               New_Extension : Extension := Extension'Input (Stream);

            begin
               New_Extension.From_Server := False;
               Item.Client_Extensions.Append (New_Extension);
               Position := @ + 4 + New_Extension.Size;
               exit when Position >= Item.Extensions_Length;
            end;
         end loop;
      end;
   end Read_Handshake_Client_Hello_Record;

   -----------------------------------
   -- Handshake_Server_Hello_Record --
   -----------------------------------

   procedure Assign_Sizes_For_Handshake_Server_Hello_Record (Item : in out Handshake_Server_Hello_Record) is
   begin
      Item.Extensions_Length := 0;

      for This_Extension of Item.Server_Extensions
      loop
         if not This_Extension.Size_Assigned
         then
            Assign_Extension_Size (This_Extension);
         end if;
         Item.Extensions_Length := @ + 4 + This_Extension.Size;
      end loop;
      Item.Message_Length := 2 + 1 + 2 + (1 + Item.Server_Session_ID.Element'Length) + 32 + 2 + 2 + Unsigned_24 (Item.Extensions_Length);
      Item.Record_Length  := Unsigned_16 (Item.Message_Length + 3 + 1);
   end Assign_Sizes_For_Handshake_Server_Hello_Record;

      --  Handshake_Server_Hello_Record Stream Management

   procedure Write_Handshake_Server_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : Handshake_Server_Hello_Record) is

      To_Write : Handshake_Server_Hello_Record := Item;

   begin
      Assign_Sizes_For_Handshake_Server_Hello_Record (To_Write);
      Write_Handshake_Record (Stream, To_Write);
      Ada.Text_IO.Put_Line (To_Write'Image);

      Protocol_Versions'Write (Stream, To_Write.Server_Protocol_Version);
      String'Write (Stream, To_Write.Server_Random);
      Unsigned_8'Write (Stream, To_Write.Server_Session_ID.Element'Length);
      String'Write (Stream, To_Write.Server_Session_ID.Element);
      Cipher_Suites'Write (Stream, To_Write.Server_Cipher_Suite);
      Compression_Methods'Write (Stream, To_Write.Server_Compression_Method);
      Unsigned_16'Write (Stream, Item.Extensions_Length);

      for This_Extension of Item.Server_Extensions
      loop
         declare
            --  Bad!

         Modifiable_Extension : Extension := This_Extension;

         begin
            Modifiable_Extension.From_Server := True;
            Extension'Write (Stream, Modifiable_Extension);
         end;
      end loop;
   end Write_Handshake_Server_Hello_Record;

   --  procedure Read_Handshake_Server_Hello_Record (Stream : not null access Root_Stream_Type'Class; Item : out Handshake_Server_Hello_Record) is
   --  begin
   --     --  TODO;
   --     Read_Handshake_Record (Stream, Item);
   --  end Read_Handshake_Server_Hello_Record;

   ----------------------------
   --                        --
   -- PRIVATE IMPLEMENTATION --
   --                        --
   ----------------------------

   ------------------------
   -- TLS Stream/Wrapper --
   ------------------------

   overriding
   procedure Read (Stream : in out TLS_Stream_Type; Item : out Stream_Element_Array; Last : out Stream_Element_Offset) is
   begin
      if Stream.TLS_Active
      then
         raise Program_Error with "Abacaba";

      else
         Stream.Raw_Stream.Read (Item, Last);
      end if;
   end Read;

   overriding
   procedure Write (Stream : in out TLS_Stream_Type; Item : Stream_Element_Array) is
   begin
      if Stream.TLS_Active
      then
         raise Program_Error with "Abacaba2";

      else
         Stream.Raw_Stream.Write (Item);
      end if;
   end Write;

end TLS;
