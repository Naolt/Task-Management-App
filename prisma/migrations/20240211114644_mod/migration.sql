-- AlterTable
ALTER TABLE "ProjectMembers" ADD COLUMN     "can_edit" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "can_view" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable
ALTER TABLE "Task" ALTER COLUMN "completed" SET DEFAULT 'backlog',
ALTER COLUMN "completed" SET DATA TYPE TEXT;
