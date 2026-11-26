//! Wireshark-style text formatting for [`Ipv4Header`]
//! (or at least an attempt at it).

use std::fmt;

use crate::{
    FIELD_INDENT,
    layer3::ipv4::{HeaderField, Ipv4Header, dscp_name, ecn_keyword},
};

impl fmt::Display for Ipv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Internet Protocol Version 4, Src: {}, Dst: {}",
            self.source_address, self.destination_address
        )?;

        writeln!(f, "{FIELD_INDENT}Version: {}", self.version)?;

        writeln!(
            f,
            "{FIELD_INDENT}Header Length: {} bytes ({})",
            self.ihl * 4,
            self.ihl
        )?;
        self.write_field_anomalies(f, HeaderField::HeaderLength)?;

        writeln!(
            f,
            "{FIELD_INDENT}Differentiated Services Field: {:#04x} (DSCP: {}, ECN: {})",
            (self.dscp << 2) | self.ecn,
            dscp_name(self.dscp),
            ecn_keyword(self.ecn),
        )?;

        writeln!(f, "{FIELD_INDENT}Total Length: {}", self.total_length)?;
        self.write_field_anomalies(f, HeaderField::TotalLength)?;

        writeln!(
            f,
            "{FIELD_INDENT}Identification: {:#06x} ({})",
            self.identification, self.identification
        )?;

        writeln!(
            f,
            "{FIELD_INDENT}Flags: {:#04x}, {}",
            self.flags.as_byte(),
            self.flags
        )?;
        self.write_field_anomalies(f, HeaderField::Flags)?;

        writeln!(f, "{FIELD_INDENT}Fragment Offset: {}", self.fragment_offset)?;
        writeln!(f, "{FIELD_INDENT}Time to Live: {}", self.ttl)?;
        writeln!(
            f,
            "{FIELD_INDENT}Protocol: {} ({})",
            self.protocol,
            self.protocol.value()
        )?;
        writeln!(
            f,
            "{FIELD_INDENT}Header Checksum: {:#06x} [{}]",
            self.header_checksum, self.checksum_status
        )?;
        self.checksum_status.write_status(f, "Header Checksum")?;
        writeln!(f, "{FIELD_INDENT}Source Address: {}", self.source_address)?;
        writeln!(
            f,
            "{FIELD_INDENT}Destination Address: {}",
            self.destination_address
        )?;

        Ok(())
    }
}

impl Ipv4Header {
    fn write_field_anomalies(
        &self,
        f: &mut fmt::Formatter<'_>,
        target: HeaderField,
    ) -> fmt::Result {
        for anomaly in self.anomalies.iter().filter(|a| a.field() == target) {
            writeln!(f, "{FIELD_INDENT}{FIELD_INDENT}[Expert Info: {anomaly}]")?;
        }
        Ok(())
    }
}
