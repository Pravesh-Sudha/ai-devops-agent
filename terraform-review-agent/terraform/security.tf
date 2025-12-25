resource "aws_security_group" "mario_ecs_sg" {
  name        = "allow-http-for-ecs"
  description = "Allow HTTP inbound traffic and all outbound traffic"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = "${var.project_name}_ecs_sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "mario_ecs_sg_ipv422" {
  security_group_id            = aws_security_group.mario_ecs_sg.id
  referenced_security_group_id = aws_security_group.mario_alb_sg.id
  from_port                    = 80
  ip_protocol                  = "tcp"
  to_port                      = 80
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ecs" {
  security_group_id = aws_security_group.mario_ecs_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

resource "aws_security_group" "mario_alb_sg" {
  name        = "allow-http-for-alb"
  description = "Allow HTTP inbound traffic and all outbound traffic"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = "${var.project_name}_alb_sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "mario_alb_sg_ipv4" {
  security_group_id = aws_security_group.mario_alb_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic" {
  security_group_id = aws_security_group.mario_alb_sg.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
