resource "aws_security_group" "open" {
  name = "open-egress"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.open.id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
