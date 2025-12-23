resource "aws_ecs_cluster" "mario_cluster" {
  name = "${var.project_name}-cluster"
  tags = {
    Name = "${var.project_name}-cluster"
  }
}

resource "aws_ecs_task_definition" "mario_task" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  container_definitions = jsonencode([
    {
      name      = "mario-game"
      image     = "sevenajay/mario:latest"
      essential = true
      portMappings = [
        {
          containerPort = 80
          hostPort      = 80
          protocol      = "tcp"
        }
      ]
    }
  ])
  tags = {
    Name = "${var.project_name}-task"
  }
}

resource "aws_ecs_service" "mario_service" {
  name            = "${var.project_name}-service"
  cluster         = aws_ecs_cluster.mario_cluster.id
  task_definition = aws_ecs_task_definition.mario_task.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = module.vpc.public_subnets
    security_groups  = [aws_security_group.mario_ecs_sg.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app_tg.arn
    container_name   = "${var.project_name}"
    container_port   = 80
  }

  tags = {
    Name = "${var.project_name}-service"
  }
}
