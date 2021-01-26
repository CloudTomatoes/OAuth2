<?php
namespace Neos\Flow\Persistence\Doctrine\Migrations;

use Doctrine\Migrations\AbstractMigration;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Migrations\AbortMigrationException;

/**
 * Auto-generated Migration: Please modify to your needs! This block will be used as the migration description if getDescription() is not used.
 */
class Version20210126154332 extends AbstractMigration
{

    /**
     * @return string
     */
    public function getDescription(): string
    {
        return '';
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException
     */
    public function up(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');
        $this->addSql('DROP INDEX flow_identity_cloudtomatoes_oauth2_domain_model_provider ON cloudtomatoes_oauth2_domain_model_provider');
        $this->addSql('CREATE UNIQUE INDEX flow_identity_cloudtomatoes_oauth2_domain_model_provider ON cloudtomatoes_oauth2_domain_model_provider (name)');
    }

    /**
     * @param Schema $schema
     * @return void
     * @throws AbortMigrationException
     */
    public function down(Schema $schema): void
    {
        $this->abortIf($this->connection->getDatabasePlatform()->getName() !== 'mysql', 'Migration can only be executed safely on "mysql".');
        $this->addSql('DROP INDEX flow_identity_cloudtomatoes_oauth2_domain_model_provider ON cloudtomatoes_oauth2_domain_model_provider');
        $this->addSql('CREATE UNIQUE INDEX flow_identity_cloudtomatoes_oauth2_domain_model_provider ON cloudtomatoes_oauth2_domain_model_provider (oauthclient)');
    }
}
